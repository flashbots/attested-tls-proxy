//! A single-use pool of preconnected byte streams. No transport or proxy policy
//! lives here: the caller supplies a connector and drives `maintain` alongside
//! acquisition. Dropping the pool cancels only unassigned work; acquisitions own
//! their streams/futures and capacity permits independently.

use std::{
    collections::VecDeque,
    fmt::Display,
    future::{Future, poll_fn},
    io,
    num::NonZeroUsize,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::{OwnedSemaphorePermit, Semaphore, mpsc},
    time::Sleep,
};

const PREFIX_LIMIT: usize = 16 * 1024;
type Connecting<S, E> = Pin<Box<dyn Future<Output = Result<S, Error<E>>> + Send>>;
type SlotWaiter = Pin<Box<dyn Future<Output = OwnedSemaphorePermit> + Send>>;

/// Settings for an optional pool of unused, prepared tunnel connections.
#[derive(Clone, Copy, Debug)]
pub struct WarmPoolOptions {
    /// Desired number of ready plus warming connections. Zero disables pooling.
    pub size: usize,
    /// Maximum unused lifetime, measured from preparation completion.
    pub max_age: Duration,
    /// Maximum concurrent background connection attempts.
    pub refill_concurrency: NonZeroUsize,
}

impl Default for WarmPoolOptions {
    fn default() -> Self {
        Self {
            size: 0,
            max_age: Duration::from_secs(60),
            refill_concurrency: NonZeroUsize::new(1).unwrap(),
        }
    }
}

#[derive(Debug)]
pub(super) enum Error<E> {
    Connect(E),
    Timeout,
}

enum State<S, E> {
    Warming(Connecting<S, E>),
    Ready {
        stream: S,
        prefix: Vec<u8>,
        expires: Pin<Box<Sleep>>,
    },
}

struct Entry<S, E> {
    state: State<S, E>,
    permit: OwnedSemaphorePermit,
}

/// The permit stays with the stream until forwarding finishes. Reads replay the
/// idle prefix; writes and half-closes are delegated without interpretation.
pub(super) struct Connection<S> {
    stream: S,
    prefix: Vec<u8>,
    offset: usize,
    _permit: OwnedSemaphorePermit,
}

impl<S: AsyncRead + Unpin> AsyncRead for Connection<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.offset < this.prefix.len() {
            let count = buf.remaining().min(this.prefix.len() - this.offset);
            buf.put_slice(&this.prefix[this.offset..this.offset + count]);
            this.offset += count;
            if this.offset == this.prefix.len() {
                this.prefix = Vec::new();
                this.offset = 0;
            }
            Poll::Ready(Ok(()))
        } else {
            Pin::new(&mut this.stream).poll_read(cx, buf)
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Connection<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().stream).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_shutdown(cx)
    }
}

pub(super) struct Acquisition<S, E> {
    entry: Entry<S, E>,
    handed_off: mpsc::Sender<()>,
}

impl<S, E> Acquisition<S, E> {
    pub async fn connect(self) -> Result<Connection<S>, Error<E>> {
        let (stream, prefix) = match self.entry.state {
            State::Warming(connect) => (connect.await?, Vec::new()),
            State::Ready { stream, prefix, .. } => (stream, prefix),
        };
        // One pending notification is enough to reset backoff. The pool may
        // already have been dropped during graceful shutdown.
        let _ = self.handed_off.try_send(());
        Ok(Connection {
            stream,
            prefix,
            offset: 0,
            _permit: self.entry.permit,
        })
    }
}

pub(super) struct Pool<C, S, E> {
    connector: C,
    options: WarmPoolOptions,
    setup_timeout: Duration,
    slots: Arc<Semaphore>,
    entries: VecDeque<Entry<S, E>>,
    slot_waiter: Option<SlotWaiter>,
    retry_delay: Duration,
    retry_at: Option<Pin<Box<Sleep>>>,
    handed_off: mpsc::Sender<()>,
    handoffs: mpsc::Receiver<()>,
}

impl<C, F, S, E> Pool<C, S, E>
where
    C: FnMut() -> F,
    F: Future<Output = Result<S, E>> + Send + 'static,
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    E: Display + Send + 'static,
{
    pub fn new(
        options: WarmPoolOptions,
        setup_timeout: Duration,
        slots: Arc<Semaphore>,
        connector: C,
    ) -> Self {
        let (handed_off, handoffs) = mpsc::channel(1);
        Self {
            connector,
            options,
            setup_timeout,
            slots,
            entries: VecDeque::new(),
            slot_waiter: None,
            retry_delay: Duration::ZERO,
            retry_at: None,
            handed_off,
            handoffs,
        }
    }

    fn connecting(&mut self, permit: OwnedSemaphorePermit) -> Entry<S, E> {
        // Start the deadline when capacity is reserved, not when first polled.
        let connect = tokio::time::timeout(self.setup_timeout, (self.connector)());
        Entry {
            state: State::Warming(Box::pin(async move {
                connect
                    .await
                    .map_err(|_| Error::Timeout)?
                    .map_err(Error::Connect)
            })),
            permit,
        }
    }

    fn failed(&mut self) {
        self.retry_delay = (self.retry_delay * 2)
            .max(Duration::from_secs(1))
            .min(Duration::from_secs(30));
        self.retry_at = Some(Box::pin(tokio::time::sleep(self.retry_delay)));
        // Do not hold a reserved capacity slot during backoff.
        self.slot_waiter = None;
    }

    fn log_inventory(&self) {
        let ready = self
            .entries
            .iter()
            .filter(|entry| matches!(entry.state, State::Ready { .. }))
            .count();
        let warming = self.entries.len() - ready;
        tracing::debug!(ready, warming, "Warm pool inventory");
    }

    /// Observe completed setups, expired entries and idle transport errors before
    /// handing out a stream. Reads are bounded and never discard application data.
    fn poll_entries(&mut self, cx: &mut Context<'_>) {
        if self.handoffs.poll_recv(cx).is_ready() {
            self.retry_delay = Duration::ZERO;
            self.retry_at = None;
            // Register again after consuming the notification.
            cx.waker().wake_by_ref();
        }
        let mut index = 0;
        while index < self.entries.len() {
            let mut remove = false;
            let mut failed = false;
            let entry = &mut self.entries[index];
            if let State::Warming(connect) = &mut entry.state {
                match connect.as_mut().poll(cx) {
                    Poll::Ready(Ok(stream)) => {
                        tracing::debug!("Pool connection prepared");
                        entry.state = State::Ready {
                            stream,
                            prefix: Vec::new(),
                            expires: Box::pin(tokio::time::sleep(self.options.max_age)),
                        };
                    }
                    Poll::Ready(Err(error)) => {
                        match error {
                            Error::Connect(error) => tracing::warn!(%error, "Pool refill failed"),
                            Error::Timeout => tracing::warn!("Pool refill timed out"),
                        }
                        remove = true;
                        failed = true;
                    }
                    Poll::Pending => {}
                }
            }
            if let State::Ready {
                stream,
                prefix,
                expires,
            } = &mut entry.state
            {
                if expires.as_mut().poll(cx).is_ready() {
                    tracing::debug!("Unused pool connection expired");
                    remove = true;
                } else if prefix.len() < PREFIX_LIMIT {
                    let mut bytes = [0; PREFIX_LIMIT];
                    let mut buf = ReadBuf::new(&mut bytes[..PREFIX_LIMIT - prefix.len()]);
                    match Pin::new(stream).poll_read(cx, &mut buf) {
                        Poll::Ready(Ok(())) if !buf.filled().is_empty() => {
                            prefix.extend_from_slice(buf.filled());
                            // Continue monitoring until Pending, EOF or buffer full.
                            cx.waker().wake_by_ref();
                        }
                        Poll::Ready(result) => {
                            tracing::debug!(?result, "Unused pool connection closed");
                            remove = true;
                            failed = true;
                        }
                        Poll::Pending => {}
                    }
                }
            }
            if remove {
                self.entries.remove(index);
                if failed {
                    self.failed();
                }
            } else {
                index += 1;
            }
        }
    }

    /// Immediately reserve ownership; never queue sources waiting for capacity.
    /// Maintenance is polled first so known-dead entries cannot be handed out.
    pub async fn acquire(&mut self) -> Option<Acquisition<S, E>> {
        poll_fn(|cx| {
            self.poll_entries(cx);
            // A background semaphore waiter may have been assigned a permit.
            // Release it before trying on-demand admission.
            self.slot_waiter = None;
            let entry = if let Some(index) = self
                .entries
                .iter()
                .enumerate()
                .filter_map(|(index, entry)| match &entry.state {
                    State::Ready { expires, .. } => Some((index, expires.deadline())),
                    State::Warming(_) => None,
                })
                .min_by_key(|(_, deadline)| *deadline)
                .map(|(index, _)| index)
            {
                tracing::debug!("Warm pool hit");
                self.entries.remove(index)
            } else if let Ok(permit) = self.slots.clone().try_acquire_owned() {
                tracing::debug!("Warm pool miss; connecting on demand");
                Some(self.connecting(permit))
            } else {
                tracing::debug!("Warm pool miss; claiming warm-up if available");
                self.entries.pop_front()
            };
            self.log_inventory();
            Poll::Ready(entry.map(|entry| Acquisition {
                entry,
                handed_off: self.handed_off.clone(),
            }))
        })
        .await
    }

    /// Drive background work alongside source acceptance. This future never
    /// completes and is cancellation-safe: all state belongs to `self`.
    pub async fn maintain(&mut self) {
        poll_fn(|cx| {
            self.poll_entries(cx);
            if let Some(retry_at) = &mut self.retry_at {
                if retry_at.as_mut().poll(cx).is_pending() {
                    return Poll::<()>::Pending;
                }
                self.retry_at = None;
            }
            let warming = self
                .entries
                .iter()
                .filter(|entry| matches!(entry.state, State::Warming(_)))
                .count();
            let needed = self.options.size.saturating_sub(self.entries.len()).min(
                self.options
                    .refill_concurrency
                    .get()
                    .saturating_sub(warming),
            );
            for _ in 0..needed {
                let waiter = self.slot_waiter.get_or_insert_with(|| {
                    let slots = self.slots.clone();
                    Box::pin(async move {
                        slots
                            .acquire_owned()
                            .await
                            .expect("pool capacity semaphore is never closed")
                    })
                });
                let Poll::Ready(permit) = waiter.as_mut().poll(cx) else {
                    break;
                };
                self.slot_waiter = None;
                let entry = self.connecting(permit);
                self.entries.push_back(entry);
                self.log_inventory();
                // Poll the newly created setup futures on the next turn.
                cx.waker().wake_by_ref();
            }
            Poll::<()>::Pending
        })
        .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt, DuplexStream, duplex},
        sync::oneshot,
        time::Instant,
    };

    type Answer = oneshot::Sender<io::Result<DuplexStream>>;
    type TestConnector =
        Box<dyn FnMut() -> Pin<Box<dyn Future<Output = io::Result<DuplexStream>> + Send>>>;
    type TestPool = Pool<TestConnector, DuplexStream, io::Error>;

    fn controlled(
        size: usize,
        cap: usize,
        concurrency: usize,
    ) -> (TestPool, mpsc::UnboundedReceiver<Answer>, Arc<Semaphore>) {
        let slots = Arc::new(Semaphore::new(cap));
        let (tx, rx) = mpsc::unbounded_channel();
        let connector: TestConnector = Box::new(move || {
            let (answer, response) = oneshot::channel();
            tx.send(answer).unwrap();
            Box::pin(async move { response.await.unwrap() })
        });
        let pool = Pool::new(
            WarmPoolOptions {
                size,
                refill_concurrency: NonZeroUsize::new(concurrency).unwrap(),
                ..WarmPoolOptions::default()
            },
            Duration::from_secs(10),
            slots.clone(),
            connector,
        );
        (pool, rx, slots)
    }

    async fn tick(pool: &mut TestPool) {
        let maintenance = pool.maintain();
        tokio::pin!(maintenance);
        poll_fn(|cx| {
            assert!(maintenance.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
    }

    fn complete(answer: Answer) -> DuplexStream {
        let (stream, peer) = duplex(64 * 1024);
        answer.send(Ok(stream)).unwrap();
        peer
    }

    #[tokio::test(start_paused = true)]
    async fn ready_fifo_refill_and_permits_follow_acquired_streams() {
        let (mut pool, mut attempts, slots) = controlled(2, 3, 2);
        assert!(attempts.try_recv().is_err()); // Configuration alone does no work.
        tick(&mut pool).await;
        let mut first = complete(attempts.try_recv().unwrap());
        let mut second = complete(attempts.try_recv().unwrap());
        first.write_all(b"first").await.unwrap();
        second.write_all(b"second").await.unwrap();
        tick(&mut pool).await;
        let mut acquired = pool.acquire().await.unwrap().connect().await.unwrap();
        let mut bytes = [0; 5];
        acquired.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"first");
        assert_eq!(slots.available_permits(), 1);
        tick(&mut pool).await;
        let warming = attempts.try_recv().unwrap();
        assert_eq!(slots.available_permits(), 0);
        let mut next = pool.acquire().await.unwrap().connect().await.unwrap();
        let mut bytes = [0; 6];
        next.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"second");
        drop(pool);
        assert!(warming.is_closed());
        assert_eq!(slots.available_permits(), 1);
        // Dropping the pool does not interrupt handed-off streams.
        acquired.write_all(b"live").await.unwrap();
        let mut bytes = [0; 4];
        first.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"live");
        drop(acquired);
        drop(next);
        assert_eq!(slots.available_permits(), 3);
    }

    #[tokio::test(start_paused = true)]
    async fn oldest_ready_means_preparation_order_not_attempt_order() {
        let (mut pool, mut attempts, _) = controlled(2, 2, 2);
        tick(&mut pool).await;
        let slow = attempts.try_recv().unwrap();
        let mut early = complete(attempts.try_recv().unwrap());
        early.write_all(b"early").await.unwrap();
        tick(&mut pool).await;
        tokio::time::advance(Duration::from_secs(1)).await;
        let mut late = complete(slow);
        late.write_all(b"late").await.unwrap();
        tick(&mut pool).await;
        let mut acquired = pool.acquire().await.unwrap().connect().await.unwrap();
        let mut bytes = [0; 5];
        acquired.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"early");
    }

    #[tokio::test(start_paused = true)]
    async fn miss_connects_on_demand_then_claims_oldest_warmup_at_capacity() {
        let (mut pool, mut attempts, slots) = controlled(2, 2, 1);
        tick(&mut pool).await;
        let background = attempts.try_recv().unwrap();
        // A spare slot means a fresh attempt, not waiting for background work.
        let fresh = pool.acquire().await.unwrap();
        let demand = attempts.try_recv().unwrap();
        let claimed = pool.acquire().await.unwrap();
        assert!(pool.acquire().await.is_none());
        assert!(attempts.try_recv().is_err());
        let _fresh_peer = complete(demand);
        let _claimed_peer = complete(background);
        let fresh = fresh.connect().await.unwrap();
        let claimed = claimed.connect().await.unwrap();
        tick(&mut pool).await;
        assert!(attempts.try_recv().is_err());
        assert_eq!(slots.available_permits(), 0);
        drop(fresh);
        tick(&mut pool).await;
        assert!(attempts.try_recv().is_ok());
        drop(claimed);
    }

    #[tokio::test(start_paused = true)]
    async fn claiming_warmup_keeps_original_deadline_and_survives_pool_drop() {
        let (mut pool, mut attempts, slots) = controlled(1, 1, 1);
        tick(&mut pool).await;
        let pending = attempts.try_recv().unwrap();
        tokio::time::advance(Duration::from_secs(8)).await;
        let claimed = pool.acquire().await.unwrap();
        drop(pool);
        let start = Instant::now();
        assert!(matches!(claimed.connect().await, Err(Error::Timeout)));
        assert_eq!(Instant::now() - start, Duration::from_secs(2));
        assert!(pending.is_closed());
        assert_eq!(slots.available_permits(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn long_timeouts_and_acquired_warmups_survive_pool_drop() {
        let (mut pool, mut attempts, slots) = controlled(1, 1, 1);
        pool.setup_timeout = Duration::MAX;
        tick(&mut pool).await;
        let pending = attempts.try_recv().unwrap();
        let acquired = pool.acquire().await.unwrap();
        drop(pool);
        let mut peer = complete(pending);
        let mut stream = acquired.connect().await.unwrap();
        stream.write_all(b"still live").await.unwrap();
        let mut bytes = [0; 10];
        peer.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"still live");
        drop(stream);
        assert_eq!(slots.available_permits(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn idle_reads_do_not_refresh_age_and_expiry_does_not_affect_active_streams() {
        let (mut pool, mut attempts, _) = controlled(2, 2, 2);
        tick(&mut pool).await;
        let mut idle = complete(attempts.try_recv().unwrap());
        let _active_peer = complete(attempts.try_recv().unwrap());
        tick(&mut pool).await;
        let active = pool.entries.remove(1).unwrap();
        let active = Acquisition {
            entry: active,
            handed_off: pool.handed_off.clone(),
        }
        .connect()
        .await
        .unwrap();
        tokio::time::advance(Duration::from_secs(59)).await;
        idle.write_all(b"late greeting").await.unwrap();
        tick(&mut pool).await;
        assert!(attempts.try_recv().is_err());
        tokio::time::advance(Duration::from_secs(1)).await;
        tick(&mut pool).await;
        let _replacement = attempts.try_recv().unwrap();
        assert_eq!(idle.read(&mut [0; 1]).await.unwrap(), 0);
        assert!(pool.acquire().await.is_some()); // Replacement warm-up is claimable.
        drop(active);
    }

    #[tokio::test(start_paused = true)]
    async fn bounded_prefix_replays_once_and_preserves_half_closes() {
        let (mut pool, mut attempts, _) = controlled(1, 1, 1);
        tick(&mut pool).await;
        let mut peer = complete(attempts.try_recv().unwrap());
        let payload: Vec<u8> = (0..PREFIX_LIMIT * 2).map(|n| (n % 251) as u8).collect();
        peer.write_all(&payload).await.unwrap();
        tick(&mut pool).await;
        let State::Ready { prefix, .. } = &pool.entries[0].state else {
            panic!("not ready")
        };
        assert_eq!(prefix.len(), PREFIX_LIMIT);
        peer.shutdown().await.unwrap();
        tick(&mut pool).await; // Full buffer stops reads, even when EOF follows.
        let mut acquired = pool.acquire().await.unwrap().connect().await.unwrap();
        let mut received = Vec::new();
        acquired.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, payload);
        acquired.write_all(b"after EOF").await.unwrap();
        acquired.shutdown().await.unwrap();
        let mut received = Vec::new();
        peer.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, b"after EOF");
    }

    #[tokio::test(start_paused = true)]
    async fn failures_back_off_including_immediate_idle_eof_and_reset_on_handoff() {
        let (mut pool, mut attempts, _) = controlled(1, 1, 1);
        tick(&mut pool).await;
        for seconds in [1, 2, 4, 8, 16, 30, 30] {
            drop(complete(attempts.try_recv().unwrap()));
            tick(&mut pool).await;
            assert!(attempts.try_recv().is_err());
            tokio::time::advance(Duration::from_secs(seconds - 1)).await;
            tick(&mut pool).await;
            assert!(attempts.try_recv().is_err());
            tokio::time::advance(Duration::from_secs(1)).await;
            tick(&mut pool).await;
        }
        attempts
            .try_recv()
            .unwrap()
            .send(Err(io::Error::other("unavailable")))
            .unwrap();
        tick(&mut pool).await;
        // On-demand work bypasses background backoff.
        let acquisition = pool.acquire().await.unwrap();
        let _peer = complete(attempts.try_recv().unwrap());
        let active = acquisition.connect().await.unwrap();
        tick(&mut pool).await;
        assert_eq!(pool.retry_delay, Duration::ZERO);
        drop(active);
        tick(&mut pool).await;
        let _peer = complete(attempts.try_recv().unwrap());
        tick(&mut pool).await;
        assert!(matches!(pool.entries[0].state, State::Ready { .. }));
    }

    #[tokio::test(start_paused = true)]
    async fn known_dead_ready_connection_is_discarded_before_handoff() {
        let (mut pool, mut attempts, slots) = controlled(1, 1, 1);
        tick(&mut pool).await;
        let peer = complete(attempts.try_recv().unwrap());
        tick(&mut pool).await;
        drop(peer);
        let acquisition = pool.acquire().await.unwrap();
        let replacement = attempts.try_recv().unwrap();
        assert_eq!(slots.available_permits(), 0);
        drop(acquisition);
        assert!(replacement.is_closed());
        assert_eq!(slots.available_permits(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn background_concurrency_and_setup_timeout_are_bounded() {
        let (mut pool, mut attempts, slots) = controlled(3, 3, 1);
        tick(&mut pool).await;
        let pending = attempts.try_recv().unwrap();
        tick(&mut pool).await;
        assert!(attempts.try_recv().is_err());
        tokio::time::advance(Duration::from_secs(10)).await;
        tick(&mut pool).await;
        assert!(pending.is_closed());
        assert_eq!(slots.available_permits(), 3);
        assert!(attempts.try_recv().is_err());
        tokio::time::advance(Duration::from_secs(1)).await;
        tick(&mut pool).await;
        let _peer = complete(attempts.try_recv().unwrap());
        tick(&mut pool).await;
        assert!(attempts.try_recv().is_ok());
        assert!(attempts.try_recv().is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn capacity_release_wakes_maintenance_without_a_timer() {
        let (mut pool, mut attempts, slots) = controlled(1, 1, 1);
        let acquisition = pool.acquire().await.unwrap();
        let _peer = complete(attempts.try_recv().unwrap());
        let active = acquisition.connect().await.unwrap();
        let start = Instant::now();
        let maintenance = pool.maintain();
        tokio::pin!(maintenance);
        tokio::select! {
            _ = &mut maintenance => unreachable!(),
            _ = tokio::task::yield_now() => {}
        }
        assert_eq!(slots.available_permits(), 0);
        drop(active);
        tokio::select! {
            biased;
            _ = &mut maintenance => unreachable!(),
            result = attempts.recv() => assert!(result.is_some()),
        }
        assert_eq!(Instant::now(), start);
    }
}
