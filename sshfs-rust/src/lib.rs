use rand::Rng;

#[no_mangle]
pub extern "C" fn random_string(s_ptr: *mut core::ffi::c_char, length: core::ffi::c_int) {
	for idx in 0..length {
		unsafe {
			*s_ptr.offset(idx.try_into().unwrap()) = (b'0' as core::ffi::c_char) + rand::thread_rng().gen_range(0..10);
		}
	}
	unsafe {
		*s_ptr.offset(length.try_into().unwrap()) = 0;
	}
}

#[no_mangle]
pub extern "C" fn sshfs_do_rename(from_path: *mut core::ffi::c_char, to_path: *mut core::ffi::c_char) -> core::ffi::c_int {
	0 as core::ffi::c_int
}
