const SSH_FXP_REMOVE: u8 = 13;
const SSH_FXP_STATUS: u8 = 101;

extern "C" {
    fn sshfs_base_path() -> *const core::ffi::c_char;
}

#[repr(C)]
struct Buffer_sys {
	p: *const u8,
	len: usize,
	size: usize
}

struct Buffer {
	p: Vec<u8>,
	len: usize
}

impl Buffer {
	fn new (size: usize) -> Self {
		let mut p = Vec::with_capacity(size);
		for _ in 0..size {
			p.push(0);
		}
		Buffer {
			p,
			len: 0,
		}
	}
	fn resize (&mut self, len: usize) {
		let new_len = (self.len+len+63)-(self.len+len+63)%32;
		if new_len > self.p.capacity() {
			self.p.reserve(new_len - self.p.capacity());
		}
		if new_len > self.p.len() {
			for _ in self.p.len()..new_len {
				p.push(0);
			}
		}
	}
	// 返り値のライフタイムがBuffer のライフタイムより短いとp の参照先が解放されてしまうためunsafe
	unsafe fn translate_into_sys (&self) -> Buffer_sys {
		Buffer_sys {
			p: self.p.as_ptr(),
			len: self.len,
			size: self.p.len()
		}
	}
	fn add (&mut self, data: &[u8]) {
		if self.len+data.len() > self.p.len() {
			self.resize(data.len());
		}
		for b in data {
			self.p[self.len] = b;
			self.len += 1;
		}
	}
}

extern "C" {
	fn get_conn(sshfs_file: *const core::ffi::c_void, path: *const core::ffi::c_void) -> *mut core::ffi::c_void;
	fn sftp_request(conn: *mut core::ffi::c_void, ssh_op_type: u8, buf: *const Buffer_sys, expect_type: u8, outbuf: *mut Buffer_sys) -> core::ffi::c_int;
}

fn get_real_path (path: *const core::ffi::c_char) -> Vec<u8> {
	let base_path = unsafe { sshfs_base_path() };
	let mut real_path = Vec::new(); 
	if unsafe { *base_path } != 0 {
		let mut base_path_len = 0;
		while unsafe { *(base_path.offset(base_path_len)) } != 0 {
			real_path.push(unsafe { *(base_path.offset(base_path_len)) as u8 });
			base_path_len += 1;
		}
		if unsafe { *(path.offset(1)) } != 0 {
    		if unsafe { *(base_path.offset(base_path_len-1)) } != b'/' as core::ffi::c_char {
	    		real_path.push(b'/');
		    }
		    let mut idx = 1;
		    while unsafe { *(path.offset(idx)) } != 0 {
				real_path.push(unsafe { *(path.offset(idx)) as u8 });
			    idx += 1;
			}
		}
	} else if unsafe { *(path.offset(1)) } != 0 {
		let mut idx = 1;
		while unsafe { *(path.offset(idx)) } != 0 {
		    real_path.push(unsafe { *(path.offset(idx)) as u8 });
		    idx += 1;
		}
	} else {
		real_path.push(b'.');
	}
	real_path
}

#[no_mangle]
pub extern "C" fn sshfs_unlink(path: *const core::ffi::c_char) -> core::ffi::c_int {
	let path = unsafe { core::ffi::CStr::from_ptr(path) };
	let path = path.to_bytes();
	0 as core::ffi::c_int
}
