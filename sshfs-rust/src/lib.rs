use rand::Rng;

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
    reqtab: *mut core::ffi::c_void,
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
    op: *mut core::ffi::c_void,
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
struct Buffer_sys {
    p: *const u8,
    len: usize,
    size: usize,
}

struct Buffer {
    p: Vec<u8>,
    len: usize,
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

impl Buffer {
    fn new(size: usize) -> Self {
        let p = vec![0;size];
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

extern "C" {
    fn get_conn(
        sshfs_file: *const core::ffi::c_void,
        path: *const core::ffi::c_void,
    ) -> Option<&'static mut Conn>;
    fn sftp_request(
        conn: Option<&mut Conn>,
        ssh_op_type: u8,
        buf: *const Buffer_sys,
        expect_type: u8,
        outbuf: *mut Buffer_sys,
    ) -> core::ffi::c_int;
    fn retrieve_sshfs() -> Option<&'static sshfs>;
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
            std::ptr::null_mut(),
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
                std::ptr::null_mut(),
            )
        }
    } else {
        -(libc::ENOSYS as core::ffi::c_int)
    }
}
