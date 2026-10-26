use std::sync::Arc;
use tokio::{sync::Semaphore, task::JoinError};

/// Bounds both running and queued blocking quote jobs across endpoint clones.
#[derive(Clone)]
pub(crate) struct QuoteWork(Arc<Semaphore>);

impl Default for QuoteWork {
    fn default() -> Self {
        Self(Arc::new(Semaphore::new(16)))
    }
}

impl QuoteWork {
    pub(crate) async fn run<F, T>(&self, generate: F) -> Result<T, JoinError>
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        // Wait before spawning: waiting inside the closure would allow an
        // unbounded queue of blocking jobs when connections are canceled.
        let permit = self.0.clone().acquire_owned().await.expect("never closed");
        tokio::task::spawn_blocking(move || {
            // A running blocking task outlives its canceled async waiter.
            let _permit = permit;
            generate()
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{future::poll_fn, task::Poll, time::Duration};
    use tokio::sync::oneshot;

    #[tokio::test]
    async fn canceled_waiter_keeps_slot_until_blocking_job_finishes() {
        let work = QuoteWork(Arc::new(Semaphore::new(1)));
        let clone = work.clone();
        let (started_tx, started_rx) = oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let waiter = tokio::spawn(async move {
            clone
                .run(move || {
                    let _ = started_tx.send(());
                    // Also terminates if the test fails and drops the sender.
                    let _ = release_rx.recv();
                })
                .await
        });
        started_rx.await.unwrap();
        waiter.abort();
        assert!(waiter.await.unwrap_err().is_cancelled());

        let (next_tx, mut next_rx) = oneshot::channel();
        let next = work.run(move || next_tx.send(()).unwrap());
        tokio::pin!(next);
        // Poll the next request while the first job is still blocked.
        poll_fn(|cx| {
            assert!(next.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        assert!(matches!(
            next_rx.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ));
        assert_eq!(work.0.available_permits(), 0);

        release_tx.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(5), next)
            .await
            .unwrap()
            .unwrap();
        next_rx.await.unwrap();
    }

    #[tokio::test]
    async fn canceling_before_acquisition_does_not_schedule_work() {
        let work = QuoteWork(Arc::new(Semaphore::new(1)));
        let permit = work.0.clone().acquire_owned().await.unwrap();
        let (tx, rx) = oneshot::channel();
        let mut waiting = Box::pin(work.run(move || {
            let _ = tx.send(());
        }));
        poll_fn(|cx| {
            assert!(waiting.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        drop(waiting);
        drop(permit);
        assert!(rx.await.is_err());
        assert_eq!(work.run(|| 42).await.unwrap(), 42);
    }

    #[tokio::test]
    async fn panicking_job_releases_slot() {
        let work = QuoteWork(Arc::new(Semaphore::new(1)));
        assert!(
            work.run(|| panic!("quote generation failed"))
                .await
                .unwrap_err()
                .is_panic()
        );
        assert_eq!(work.run(|| 42).await.unwrap(), 42);
    }
}
