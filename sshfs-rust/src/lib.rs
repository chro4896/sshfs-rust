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

#[no_mangle]
pub extern "C" fn sshfs_link(from_path: *const core::ffi::c_char, to_path: *const core::ffi::c_char) -> core::ffi::c_int {
	let from_path = unsafe { core::ffi::CStr::from_ptr(from_path) };
	let from_path = from_path.to_bytes();
	let to_path = unsafe { core::ffi::CStr::from_ptr(to_path) };
	let to_path = to_path.to_bytes();
	0 as core::ffi::c_int
}
