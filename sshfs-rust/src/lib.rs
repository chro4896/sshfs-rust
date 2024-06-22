pub fn add(left: usize, right: usize) -> usize {
    left + right
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}

#[repr(C)]
struct Buffer {
	p: *const u8,
	len: usize,
	size: usize
}

extern "C" {
	fn get_conn(sshfs_file: *const core::ffi::c_void, path: *const core::ffi::c_void) -> *mut core::ffi::c_void;
	fn sftp_request(conn: *mut core::ffi::c_void, ssh_op_type: u8, buf: *const Buffer, expect_type: u8, outbuf: *mut Buffer) -> core::ffi::c_int;
}

#[no_mangle]
pub extern "C" fn sshfs_unlink(path: *const core::ffi::c_char) -> core::ffi::c_int {
	let path = unsafe { core::ffi::CStr::from_ptr(path) };
	let path = path.to_bytes();
	0 as core::ffi::c_int
}
