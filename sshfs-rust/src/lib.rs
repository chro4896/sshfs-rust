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
