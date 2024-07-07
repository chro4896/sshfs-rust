const SSH_FXP_READ: u8 = 5;
const SSH_FXP_READDIR: u8 = 12;
const SSH_FXP_REMOVE: u8 = 13;
const SSH_FXP_RMDIR: u8 = 15;
const SSH_FXP_STATUS: u8 = 101;

const SSH_FX_OK: u32 = 0;
const SSH_FX_EOF: u32 = 1;
const SSH_FX_FAILURE: u32 4;

const MY_EOF: u8 = 1;

extern "C" {
    fn sshfs_base_path() -> *const core::ffi::c_char;
    fn sshfs_lock_ptr() -> *mut core::ffi::c_void;
}

#[repr(C)]
struct Request_ext_rust {
	want_reply: core::ffi::c_uint,
	ready: *mut libc::sem_t,
	reply_type: u8,
	id: u32,
	replied: core::ffi::c_int,
	error: core::ffi::c_int,
	reply: *mut core::ffi::c_void,
	start: libc::timeval,
	data: *mut core::ffi::c_void,
	end_func: *mut core::ffi::c_void,
	len: usize,
	list: List_head,
	conn: *mut core::ffi::c_void,
}

#[repr(C)]
struct List_head {
	prev: *mut List_head,
	next: *mut List_head,
}

pub extern "C" fn sftp_request_wait_rust(req: *mut Request_ext_rust, op_type: u8, expect_type: u8, outbuf: *mut core::ffi::c_void, req_orig: *mut core::ffi::c_void) -> core::ffi::c_int {
	let mut err = 0;
	
	let mut req = unsafe { req.as_mut().unwrap() };
	
	if req.error != 0 {
		err = req.error;
	} else {
		loop {
			if unsafe { libc::sem_wait(req.ready) } != 0 {
				break;
			}
		}
		if req.error != 0 {
			err = req.error;
		} else {
			
		}
	}
	err
}
