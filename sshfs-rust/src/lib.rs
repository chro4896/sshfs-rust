use rand::Rng;

const SSH_FXP_CLOSE: u8 = 4;
const SSH_FXP_READ: u8 = 5;
const SSH_FXP_OPENDIR: u8 = 11;
const SSH_FXP_READDIR: u8 = 12;
const SSH_FXP_REMOVE: u8 = 13;
const SSH_FXP_RMDIR: u8 = 15;
const SSH_FXP_RENAME: u8 = 18;
const SSH_FXP_STATUS: u8 = 101;
const SSH_FXP_HANDLE: u8 = 102;
const SSH_FXP_EXTENDED: u8 = 200;

const SSH_FX_OK: u32 = 0;
const SSH_FX_EOF: u32 = 1;
const SSH_FX_FAILURE: u32 = 4;

const SFTP_EXT_HARDLINK: &str = "hardlink@openssh.com";

const MY_EOF: core::ffi::c_int = 1;

#[repr(C)]
struct fuse_args {
    argc: core::ffi::c_int,
    argv: *mut *mut core::ffi::c_char,
    allocated: core::ffi::c_int,
}

type FuseFillDir = extern "C" fn(
    *mut core::ffi::c_void,
    *const core::ffi::c_char,
    *const core::ffi::c_void,
    libc::off_t,
    i32,
) -> core::ffi::c_int;

#[repr(C)]
struct fuse_operations {
    getattr: Option<
        extern "C" fn(
            *const core::ffi::c_char,
            Option<&mut libc::stat>,
            *mut core::ffi::c_void,
        ) -> core::ffi::c_int,
    >,
    readlink: Option<
        extern "C" fn(*const core::ffi::c_char, *mut core::ffi::c_char, usize) -> core::ffi::c_int,
    >,
    mknod: Option<
        extern "C" fn(*const core::ffi::c_char, libc::mode_t, libc::dev_t) -> core::ffi::c_int,
    >,
    mkdir: Option<extern "C" fn(*const core::ffi::c_char, libc::mode_t) -> core::ffi::c_int>,
    unlink: Option<extern "C" fn(*const core::ffi::c_char) -> core::ffi::c_int>,
    rmdir: Option<extern "C" fn(*const core::ffi::c_char) -> core::ffi::c_int>,
    symlink: Option<
        extern "C" fn(*const core::ffi::c_char, *const core::ffi::c_char) -> core::ffi::c_int,
    >,
    rename: Option<
        extern "C" fn(
            *const core::ffi::c_char,
            *const core::ffi::c_char,
            *const core::ffi::c_uint,
        ) -> core::ffi::c_int,
    >,
    link: Option<
        extern "C" fn(*const core::ffi::c_char, *const core::ffi::c_char) -> core::ffi::c_int,
    >,
    chmod: Option<
        extern "C" fn(
            *const core::ffi::c_char,
            libc::mode_t,
            *const core::ffi::c_void,
        ) -> core::ffi::c_int,
    >,
    chown: Option<
        extern "C" fn(
            *const core::ffi::c_char,
            libc::uid_t,
            libc::gid_t,
            *const core::ffi::c_void,
        ) -> core::ffi::c_int,
    >,
    truncate: Option<
        extern "C" fn(
            *const core::ffi::c_char,
            libc::off_t,
            *const core::ffi::c_void,
        ) -> core::ffi::c_int,
    >,
    open:
        Option<extern "C" fn(*const core::ffi::c_char, *mut core::ffi::c_void) -> core::ffi::c_int>,
    read: Option<
        extern "C" fn(
            *const core::ffi::c_char,
            *mut core::ffi::c_char,
            usize,
            libc::off_t,
            *mut core::ffi::c_void,
        ) -> core::ffi::c_int,
    >,
    write: *const core::ffi::c_void,
    statfs: *const core::ffi::c_void,
    flush: *const core::ffi::c_void,
    release: *const core::ffi::c_void,
    fsync: *const core::ffi::c_void,
    setxattr: *const core::ffi::c_void,
    getxattr: *const core::ffi::c_void,
    listxattr: *const core::ffi::c_void,
    removexattr: *const core::ffi::c_void,
    opendir: *const core::ffi::c_void,
    readdir: Option<
        extern "C" fn(
            *const core::ffi::c_char,
            *mut core::ffi::c_void,
            FuseFillDir,
            libc::off_t,
            *mut core::ffi::c_void,
            i32,
        ) -> core::ffi::c_int,
    >,
    releasedir: *const core::ffi::c_void,
    fsyncdir: *const core::ffi::c_void,
    init: *const core::ffi::c_void,
    destroy: *const core::ffi::c_void,
    access: *const core::ffi::c_void,
    create: *const core::ffi::c_void,
    lock: *const core::ffi::c_void,
    utimens: *const core::ffi::c_void,
    bmap: *const core::ffi::c_void,
    ioctl: *const core::ffi::c_void,
    poll: *const core::ffi::c_void,
    write_buf: *const core::ffi::c_void,
    read_buf: *const core::ffi::c_void,
    flock: *const core::ffi::c_void,
    fallocate: *const core::ffi::c_void,
    copy_file_range: *const core::ffi::c_void,
    lseek: *const core::ffi::c_void,
}

#[repr(C)]
pub struct fuse_file_info {
    flags: core::ffi::c_int,
    bitfield: u64,
    fh: u64,
    lock_owner: u64,
    poll_events: u32,
}

#[repr(C)]
struct sshfs {
    directport: *mut core::ffi::c_char,
    ssh_command: *mut core::ffi::c_char,
    sftp_server: *mut core::ffi::c_char,
    ssh_args: fuse_args,
    workarounds: *mut core::ffi::c_char,
    rename_workaround: core::ffi::c_int,
    renamexdev_workaround: core::ffi::c_int,
    truncate_workaround: core::ffi::c_int,
    buflimit_workaround: core::ffi::c_int,
    unrel_append: core::ffi::c_int,
    fstat_workaround: core::ffi::c_int,
    createmode_workaround: core::ffi::c_int,
    transform_symlinks: core::ffi::c_int,
    follow_symlinks: core::ffi::c_int,
    no_check_root: core::ffi::c_int,
    detect_uid: core::ffi::c_int,
    idmap: core::ffi::c_int,
    nomap: core::ffi::c_int,
    disable_hardlink: core::ffi::c_int,
    dir_cache: core::ffi::c_int,
    show_version: core::ffi::c_int,
    show_help: core::ffi::c_int,
    singlethread: core::ffi::c_int,
    mountpoint: *mut core::ffi::c_char,
    uid_file: *mut core::ffi::c_char,
    gid_file: *mut core::ffi::c_char,
    uid_map: *mut core::ffi::c_void,
    gid_map: *mut core::ffi::c_void,
    r_uid_map: *mut core::ffi::c_void,
    r_gid_map: *mut core::ffi::c_void,
    max_read: core::ffi::c_uint,
    max_write: core::ffi::c_uint,
    ssh_ver: core::ffi::c_uint,
    sync_write: core::ffi::c_int,
    sync_read: core::ffi::c_int,
    sync_readdir: core::ffi::c_int,
    direct_io: core::ffi::c_int,
    debug: core::ffi::c_int,
    verbose: core::ffi::c_int,
    foreground: core::ffi::c_int,
    reconnect: core::ffi::c_int,
    delay_connect: core::ffi::c_int,
    passive: core::ffi::c_int,
    host: *mut core::ffi::c_char,
    base_path: *mut core::ffi::c_char,
    reqtab: *mut std::collections::HashMap<u32, *mut Request>,
    conntab: *mut core::ffi::c_void,
    lock: libc::pthread_mutex_t,
    lock_ptr: *mut libc::pthread_mutex_t,
    randseed: core::ffi::c_uint,
    max_conns: core::ffi::c_int,
    vsock: *mut core::ffi::c_char,
    conns: *mut core::ffi::c_void,
    ptyfd: core::ffi::c_int,
    ptypassivefd: core::ffi::c_int,
    connvers: core::ffi::c_int,
    server_version: core::ffi::c_int,
    remote_uid: core::ffi::c_uint,
    local_uid: core::ffi::c_uint,
    remote_gid: core::ffi::c_uint,
    local_gid: core::ffi::c_uint,
    remote_uid_detected: core::ffi::c_int,
    blksize: core::ffi::c_uint,
    progname: *mut core::ffi::c_char,
    modifver: core::ffi::c_long,
    outstanding_len: core::ffi::c_uint,
    max_outstanding_len: core::ffi::c_uint,
    outstanding_cond: libc::pthread_cond_t,
    password_stdin: core::ffi::c_int,
    password: *mut core::ffi::c_char,
    ext_posix_rename: core::ffi::c_int,
    ext_statvfs: core::ffi::c_int,
    ext_hardlink: core::ffi::c_int,
    ext_fsync: core::ffi::c_int,
    op: *mut fuse_operations,
    bytes_sent: u64,
    bytes_received: u64,
    num_sent: u64,
    num_received: u64,
    min_rtt: core::ffi::c_uint,
    max_rtt: core::ffi::c_uint,
    total_rtt: u64,
    num_connect: core::ffi::c_uint,
}

#[repr(C)]
pub struct Buffer_sys {
    p: *const u8,
    len: usize,
    size: usize,
}

struct Buffer {
    p: Vec<u8>,
    len: usize,
}

impl Buffer {
    fn new(size: usize) -> Self {
        let p = vec![0; size];
        Buffer { p, len: 0 }
    }
    fn resize(&mut self, len: usize) {
        let new_len = (self.len + len + 63) - (self.len + len + 63) % 32;
        if new_len > self.p.capacity() {
            self.p.reserve(new_len - self.p.capacity());
        }
        if new_len > self.p.len() {
            for _ in self.p.len()..new_len {
                self.p.push(0);
            }
        }
    }
    // 返り値のライフタイムがBuffer のライフタイムより短いとp の参照先が解放されてしまうためunsafe
    unsafe fn translate_into_sys(&self) -> Buffer_sys {
        Buffer_sys {
            p: self.p.as_ptr(),
            len: self.len,
            size: self.p.len(),
        }
    }
    fn add(&mut self, data: &[u8]) {
        if self.len + data.len() > self.p.len() {
            self.resize(data.len());
        }
        for b in data {
            self.p[self.len] = *b;
            self.len += 1;
        }
    }
    fn add_u32(&mut self, data: u32) {
        self.add(&[
            ((data >> 24) & 255) as u8,
            ((data >> 16) & 255) as u8,
            ((data >> 8) & 255) as u8,
            (data & 255) as u8,
        ]);
    }
    fn add_str(&mut self, data: &[u8]) {
        self.add_u32(data.len() as u32);
        self.add(data);
    }
}

#[repr(C)]
struct Conn {
    lock_write: libc::pthread_mutex_t,
    processing_thread_started: core::ffi::c_int,
    rfd: core::ffi::c_int,
    wfd: core::ffi::c_int,
    connver: core::ffi::c_int,
    req_count: core::ffi::c_int,
    dir_count: core::ffi::c_int,
    file_count: core::ffi::c_int,
}

#[repr(C)]
struct DirHandle {
    buf: Buffer_sys,
    conn: *mut Conn,
}

type RequestFunc = extern "C" fn(
    *mut Request
);

#[repr(C)]
pub struct Request {
    want_reply: core::ffi::c_uint,
    ready: libc::sem_t,
    reply_type: u8,
    id: u32,
    replied: core::ffi::c_int,
    error: core::ffi::c_int,
    reply: Buffer_sys,
    start: libc::timeval,
    data: *mut core::ffi::c_void,
    end_func: Option<RequestFunc>,
    len: usize,
    list: List_head,
    conn: *mut Conn,
}

#[repr(C)]
struct List_head {
    prev: *mut List_head,
    next: *mut List_head,
}

#[no_mangle]
pub unsafe extern "C" fn req_table_new() -> *mut std::collections::HashMap<u32, *mut Request> {
	Box::into_raw(Box::new(std::collections::HashMap::new()))
}

#[no_mangle]
pub unsafe extern "C" fn req_table_lookup(key: u32) -> *mut Request {
	let sshfs_ref = unsafe { retrieve_sshfs().unwrap() };
	let reqtab = unsafe { &(*sshfs_ref.reqtab) };
	match reqtab.get(&key) {
		Some(req) => req.clone(),
		None => std::ptr::null_mut() as *mut Request,
	}
}

#[no_mangle]
pub extern "C" fn req_table_remove(key: u32) -> core::ffi::c_int {
	let sshfs_ref = unsafe { retrieve_sshfs().unwrap() };
	let reqtab = unsafe { &mut (*sshfs_ref.reqtab) };
	match reqtab.remove(&key) {
		Some(_) => 1,
		None => 0,
	}
}

#[no_mangle]
pub extern "C" fn req_table_insert(key: u32, val: *mut Request) {
	let sshfs_ref = unsafe { retrieve_sshfs().unwrap() };
	let reqtab = unsafe { &mut (*sshfs_ref.reqtab) };
	reqtab.insert(key, val);
}

type ClearReqFunc = extern "C" fn(
    *mut Request,
    *mut Conn,
) -> core::ffi::c_int;

#[no_mangle]
pub extern "C" fn req_table_foreach_remove(cfunc: ClearReqFunc, conn: *mut Conn) {
	let sshfs_ref = unsafe { retrieve_sshfs().unwrap() };
	let reqtab = unsafe { &(*sshfs_ref.reqtab) };
	let mut del_list = Vec::new();
	for (key, val) in reqtab.iter() {
		if cfunc(val.clone(), conn) != 0 {
			del_list.push(key);
		}
	}
	let reqtab = unsafe { &mut (*sshfs_ref.reqtab) };
	for key in del_list {
		reqtab.remove(key);
	}
}

extern "C" {
    fn buf_get_uint32(buf: *mut core::ffi::c_void, cal: *mut u32) -> core::ffi::c_int;
    fn sftp_error_to_errno(errno: u32) -> core::ffi::c_int;
    fn request_free(req: *mut Request);
    fn get_conn(sshfs_file: *const core::ffi::c_void, path: *const core::ffi::c_void) -> *mut Conn;
    fn retrieve_sshfs() -> Option<&'static mut sshfs>;
    fn sftp_get_id() -> u32;
    fn start_processing_thread(conn: *mut Conn) -> core::ffi::c_int;
    fn iov_length(iov: *mut libc::iovec, nr_segs: core::ffi::c_ulong) -> usize;
    fn type_name(ssh_type: u8) -> *const core::ffi::c_char;
    fn sftp_send_iov(conn: *mut Conn, ssh_type: u8, id: u32, iov: *mut libc::iovec, count: usize) -> core::ffi::c_int;
}

fn get_real_path(path: *const core::ffi::c_char) -> Vec<u8> {
    let base_path = unsafe { retrieve_sshfs().unwrap().base_path };
    let mut real_path = Vec::new();
    if unsafe { *base_path } != 0 {
        let mut base_path_len = 0;
        while unsafe { *(base_path.offset(base_path_len)) } != 0 {
            real_path.push(unsafe { *(base_path.offset(base_path_len)) as u8 });
            base_path_len += 1;
        }
        if unsafe { *(path.offset(1)) } != 0 {
            if unsafe { *(base_path.offset(base_path_len - 1)) } != b'/' as core::ffi::c_char {
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
pub extern "C" fn sshfs_access(
    path: *const core::ffi::c_char,
    mask: core::ffi::c_int,
) -> core::ffi::c_int {
    if (mask & libc::X_OK) == 0 {
        0
    } else {
        let sshfs_ref = unsafe { retrieve_sshfs().unwrap() };
        // 本来はスタックに持つものだが、未初期化の変数が使用できないためmalloc で確保している
        let stbuf = unsafe { libc::malloc(std::mem::size_of::<libc::stat>()) } as *mut libc::stat;
        let err = unsafe { ((*(sshfs_ref.op)).getattr.unwrap())(path, Some(&mut (*stbuf)), std::ptr::null_mut()) };
        let ret = unsafe {
            let stbuf = *stbuf;
            if err == 0 {
                0
            } else if (stbuf.st_mode & libc::S_IFREG) > 0
                && (stbuf.st_mode & (libc::S_IXUSR | libc::S_IXGRP | libc::S_IXOTH)) == 0
            {
                -(libc::EACCES as core::ffi::c_int)
            } else {
                err
            }
        };
        unsafe {
            libc::free(stbuf as *mut core::ffi::c_void);
        }
        ret
    }
}

#[no_mangle]
pub unsafe extern "C" fn sftp_request_wait(
    req: *mut Request,
    op_type: u8,
    expect_type: u8,
    outbuf: Option<&mut Buffer_sys>,
) -> core::ffi::c_int {
    let req_orig = req;
    let req = &mut (*req);
    let err = if req.error != 0 {
        req.error
    } else {
        loop {
            if libc::sem_wait(&mut req.ready as *mut libc::sem_t) == 0 {
                break;
            }
        }
        if req.error != 0 {
            req.error
        } else if req.reply_type != expect_type && req.reply_type != SSH_FXP_STATUS {
            eprintln!("protocol error");
            -libc::EIO
        } else if req.reply_type == SSH_FXP_STATUS {
            let mut serr: u32 = 0;
            if 
                buf_get_uint32(
                    &mut req.reply as *mut Buffer_sys as *mut core::ffi::c_void,
                    &mut serr as *mut u32,
                )
            != -1
            {
                match serr {
                    SSH_FX_OK => {
                        if expect_type == SSH_FXP_STATUS {
                            0
                        } else {
                            -libc::EIO
                        }
                    }
                    SSH_FX_EOF => {
                        if op_type == SSH_FXP_READ || op_type == SSH_FXP_READDIR {
                            MY_EOF
                        } else {
                            -libc::EIO
                        }
                    }
                    SSH_FX_FAILURE => {
                        if op_type == SSH_FXP_RMDIR {
                            -libc::ENOTEMPTY
                        } else {
                            -libc::EPERM
                        }
                    }
                    _ => (-1) * sftp_error_to_errno(serr),
                }
            } else {
                -libc::EIO
            }
        } else {
			let outbuf = outbuf.unwrap();
            outbuf.p =
                libc::malloc(req.reply.size - req.reply.len) as *const u8;
            if outbuf.p == (std::ptr::null_mut() as *const u8) {
                panic!("sshfs: memory allocation failed");
            }
            outbuf.len = 0;
            outbuf.size = (req.reply.size - req.reply.len) as usize;
            if req.reply.len + outbuf.size > req.reply.size {
                eprintln!("buffer too short");
            } else {
                libc::memcpy(
                    outbuf.p as *mut core::ffi::c_void,
                    req.reply.p.offset(req.reply.len.try_into().unwrap())
                        as *const core::ffi::c_void,
                    outbuf.size,
                );
                req.reply.len += outbuf.size;
            }
            0
        }
    };
    libc::pthread_mutex_lock(retrieve_sshfs().unwrap().lock_ptr);
    request_free(req_orig);
	libc::pthread_mutex_unlock(retrieve_sshfs().unwrap().lock_ptr);
    err
}

#[no_mangle]
pub unsafe extern "C" fn sftp_request_send(conn: *mut Conn, ssh_type: u8, iov: *mut libc::iovec, count: usize, begin_func: Option<RequestFunc>, end_func: Option<RequestFunc>, want_reply: core::ffi::c_uint, data: *mut core::ffi::c_void, reqp: *mut *mut Request) -> core::ffi::c_int {
	let req = libc::calloc(1, std::mem::size_of::<Request>()) as *mut Request;
	(*req).want_reply = want_reply;
	(*req).end_func = end_func;
	(*req).data = data;
	libc::sem_init(&mut ((*req).ready) as *mut libc::sem_t, 0, 0);
	(*req).reply.p = std::ptr::null() as *const u8;
	(*req).reply.len = 0;
	(*req).reply.size = 0;
    libc::pthread_mutex_lock(retrieve_sshfs().unwrap().lock_ptr);
    if let Some(func) = begin_func {
		func(req);
	}
	let id = sftp_get_id();
	(*req).id = id;
	(*req).conn = conn.clone();
	(*((*req).conn)).req_count += 1;
	let mut err = start_processing_thread(conn);
	if err != 0 {
		libc::pthread_mutex_unlock(retrieve_sshfs().unwrap().lock_ptr);
	} else {
		(*req).len = iov_length(iov, count.try_into().unwrap()) + 9;
		let sshfs_obj = retrieve_sshfs().unwrap();
		sshfs_obj.outstanding_len += <usize as TryInto<u32>>::try_into((*req).len).unwrap();
		while sshfs_obj.outstanding_len > sshfs_obj.max_outstanding_len {
    		libc::pthread_cond_wait(&mut sshfs_obj.outstanding_cond as *mut libc::pthread_cond_t, sshfs_obj.lock_ptr);
		}
		req_table_insert(id, req);
		if sshfs_obj.debug != 0 {
			libc::gettimeofday(&mut (*req).start as *mut libc::timeval, std::ptr::null_mut());
			sshfs_obj.num_sent += 1;
			sshfs_obj.bytes_sent += (*req).len as u64;
			eprintln!("{0:<5} {1}", id, core::ffi::CStr::from_ptr(type_name(ssh_type)).to_str().unwrap());
		}
		libc::pthread_mutex_unlock(retrieve_sshfs().unwrap().lock_ptr);
		err = -libc::EIO;
		if sftp_send_iov(conn, ssh_type, id, iov, count) == -1{
            libc::pthread_mutex_lock(retrieve_sshfs().unwrap().lock_ptr);
            let rmed = req_table_remove(id);
            libc::pthread_mutex_unlock(retrieve_sshfs().unwrap().lock_ptr);
            if rmed == 0 && want_reply == 0 {
				return err;
			}
		} else {
    	    if want_reply != 0 {
	    	    *reqp = req;
	        }
	        return 0;	
		}
	}
	(*req).error = err;
    if want_reply == 0 {
		sftp_request_wait(req, ssh_type, 0, None);
	} else {
	    *reqp = req;
	}
	err
}

#[no_mangle]
pub unsafe extern "C" fn sftp_request(conn: *mut Conn, ssh_type: u8, buf: *const Buffer_sys,
        expect_type: u8,
        outbuf: Option<&mut Buffer_sys>,
    ) -> core::ffi::c_int {
        // 本来はスタックに持つものだが、未初期化の変数が使用できないためmalloc で確保している
        let iov = libc::malloc(std::mem::size_of::<libc::iovec>()) as *mut libc::iovec;
        let reqp = libc::malloc(std::mem::size_of::<*mut Request>()) as *mut *mut Request;
        (*iov).iov_base = (*buf).p as *mut core::ffi::c_void;
        (*iov).iov_len = (*buf).len;
        let ret = sftp_request_send(conn, ssh_type, iov, 1, None, None, expect_type as core::ffi::c_uint, std::ptr::null_mut(), reqp);
        let ret = if expect_type == 0 {
			ret
		} else {
			sftp_request_wait(*reqp, ssh_type, expect_type, outbuf)
		};
		libc::free(iov as *mut core::ffi::c_void);
		libc::free(reqp as *mut core::ffi::c_void);
		ret
}

#[no_mangle]
pub extern "C" fn sshfs_opendir(
    path: *const core::ffi::c_char,
    fi: &mut fuse_file_info,
) -> core::ffi::c_int {
    let path = get_real_path(path);
    let mut buf = Buffer::new(0);
    buf.add_str(&path);
    let buf = unsafe { buf.translate_into_sys() };
    let handle = unsafe { libc::calloc(1, std::mem::size_of::<DirHandle>()) } as *mut DirHandle;
    unsafe {
        (*handle).conn = get_conn(std::ptr::null_mut(), std::ptr::null_mut());
    }
    let err = unsafe {
        sftp_request(
            (*handle).conn,
            SSH_FXP_OPENDIR,
            &buf,
            SSH_FXP_HANDLE,
            Some(&mut (*handle).buf),
        )
    };
    if err == 0 {
        unsafe {
            (*handle).buf.len = (*handle).buf.size;
        }
        unsafe {
            libc::pthread_mutex_lock(retrieve_sshfs().unwrap().lock_ptr);
            (*((*handle).conn)).dir_count += 1;
            libc::pthread_mutex_unlock(retrieve_sshfs().unwrap().lock_ptr);
        }
        fi.fh = handle as u64;
    } else {
        unsafe {
            libc::free(handle as *mut core::ffi::c_void);
        }
    }
    err
}

#[no_mangle]
pub extern "C" fn sshfs_unlink(path: *const core::ffi::c_char) -> core::ffi::c_int {
    let path = get_real_path(path);
    let mut buf = Buffer::new(0);
    buf.add_str(&path);
    let buf = unsafe { buf.translate_into_sys() };
    unsafe {
        sftp_request(
            get_conn(std::ptr::null_mut(), std::ptr::null_mut()),
            SSH_FXP_REMOVE,
            &buf,
            SSH_FXP_STATUS,
            None,
        )
    }
}

#[no_mangle]
pub extern "C" fn sshfs_rmdir(path: *const core::ffi::c_char) -> core::ffi::c_int {
    let path = get_real_path(path);
    let mut buf = Buffer::new(0);
    buf.add_str(&path);
    let buf = unsafe { buf.translate_into_sys() };
    unsafe {
        sftp_request(
            get_conn(std::ptr::null_mut(), std::ptr::null_mut()),
            SSH_FXP_RMDIR,
            &buf,
            SSH_FXP_STATUS,
            None,
        )
    }
}

#[no_mangle]
pub unsafe extern "C" fn random_string(s_ptr: *mut core::ffi::c_char, length: core::ffi::c_int) {
    for idx in 0..length {
        *s_ptr.offset(idx.try_into().unwrap()) =
            (b'0' as core::ffi::c_char) + rand::thread_rng().gen_range(0..10);
    }
    *s_ptr.offset(length.try_into().unwrap()) = 0;
}

#[no_mangle]
pub extern "C" fn sshfs_link(
    from_path: *const core::ffi::c_char,
    to_path: *const core::ffi::c_char,
) -> core::ffi::c_int {
    let sshfs_ref = unsafe { retrieve_sshfs().unwrap() };

    if sshfs_ref.ext_hardlink != 0 && sshfs_ref.disable_hardlink == 0 {
        let from_path = get_real_path(from_path);
        let to_path = get_real_path(to_path);
        let mut buf = Buffer::new(0);
        buf.add_str(SFTP_EXT_HARDLINK.as_bytes());
        buf.add_str(&from_path);
        buf.add_str(&to_path);
        let buf = unsafe { buf.translate_into_sys() };
        unsafe {
            sftp_request(
                get_conn(std::ptr::null_mut(), std::ptr::null_mut()),
                SSH_FXP_EXTENDED,
                &buf,
                SSH_FXP_STATUS,
                None,
            )
        }
    } else {
        -(libc::ENOSYS as core::ffi::c_int)
    }
}

#[no_mangle]
pub extern "C" fn sshfs_do_rename(
    from_path: *mut core::ffi::c_char,
    to_path: *mut core::ffi::c_char,
) -> core::ffi::c_int {
    let from_path = get_real_path(from_path);
    let to_path = get_real_path(to_path);
    let mut buf = Buffer::new(0);
    buf.add_str(&from_path);
    buf.add_str(&to_path);
    let buf = unsafe { buf.translate_into_sys() };
    unsafe {
        sftp_request(
            get_conn(std::ptr::null_mut(), std::ptr::null_mut()),
            SSH_FXP_RENAME,
            &buf,
            SSH_FXP_STATUS,
            None,
        )
    }
}
