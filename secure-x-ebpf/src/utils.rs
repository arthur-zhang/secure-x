pub mod xdp {
    use aya_ebpf::programs::XdpContext;

    #[inline(always)]
    pub unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
        let start = ctx.data();
        let end = ctx.data_end();
        let len = size_of::<T>();

        if start + offset + len > end {
            return Err(());
        }

        Ok((start + offset) as *const T)
    }
}
