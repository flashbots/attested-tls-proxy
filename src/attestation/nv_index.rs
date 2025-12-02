use tss_esapi::{
    handles::NvIndexTpmHandle,
    interface_types::{resource_handles::NvAuth, session_handles::AuthSession},
    tcti_ldr::{DeviceConfig, TctiNameConf},
    Context,
};

pub fn get_session_context() -> Result<Context, tss_esapi::Error> {
    let conf: TctiNameConf = TctiNameConf::Device(DeviceConfig::default());
    let mut context = Context::new(conf)?;
    let auth_session = AuthSession::Password;
    context.set_sessions((Some(auth_session), None, None));
    Ok(context)
}

pub fn read_nv_index(ctx: &mut Context, index: u32) -> Result<Vec<u8>, tss_esapi::Error> {
    let nv_tpm_handle = NvIndexTpmHandle::new(index)?;
    let buf = tss_esapi::abstraction::nv::read_full(ctx, NvAuth::Owner, nv_tpm_handle)?;
    Ok(buf.to_vec())
}
