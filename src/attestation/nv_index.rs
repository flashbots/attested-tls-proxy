use tss_esapi::{
    handles::NvIndexHandle,
    interface_types::{resource_handles::NvAuth, session_handles::AuthSession},
    structures::MaxNvBuffer,
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
    let handle = NvIndexHandle::from(index);
    let size = ctx
        .nv_read_public(handle)?
        .0
        .data_size()
        .try_into()
        .unwrap_or(0u16);

    let data: MaxNvBuffer = ctx.nv_read(NvAuth::Owner, handle, size, 0)?;
    Ok(data.to_vec())
}
