use rand::Rng;

const SSH_FXP_OPEN: u8 = 3;
const SSH_FXP_CLOSE: u8 = 4;
const SSH_FXP_READ: u8 = 5;
const SSH_FXP_WRITE: u8 = 6;
const SSH_FXP_LSTAT: u8 = 7;
const SSH_FXP_OPENDIR: u8 = 11;
const SSH_FXP_READDIR: u8 = 12;
const SSH_FXP_REMOVE: u8 = 13;
const SSH_FXP_MKDIR: u8 = 14;
const SSH_FXP_RMDIR: u8 = 15;
const SSH_FXP_STAT: u8 = 17;
const SSH_FXP_RENAME: u8 = 18;
const SSH_FXP_STATUS: u8 = 101;
const SSH_FXP_HANDLE: u8 = 102;
const SSH_FXP_NAME: u8 = 104;
const SSH_FXP_ATTRS: u8 = 105;
const SSH_FXP_EXTENDED: u8 = 200;

const SSH_FILEXFER_ATTR_PERMISSIONS: u32 = 4;

const SSH_FX_OK: u32 = 0;
const SSH_FX_EOF: u32 = 1;
const SSH_FX_FAILURE: u32 = 4;

const SSH_FXF_READ: u32 = 1 << 0;
const SSH_FXF_WRITE: u32 = 1 << 1;
const SSH_FXF_APPEND: u32 = 1 << 2;
const SSH_FXF_CREAT: u32 = 1 << 3;
const SSH_FXF_TRUNC: u32 = 1 << 4;
const SSH_FXF_EXCL: u32 = 1 << 5;

const SFTP_EXT_POSIX_RENAME: &str = "posix-rename@openssh.com";
const SFTP_EXT_HARDLINK: &str = "hardlink@openssh.com";

const MY_EOF: core::ffi::c_int = 1;
const RENAME_TEMP_CHARS: core::ffi::c_int = 8;

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
    access: Option<extern "C" fn(*const core::ffi::c_char, libc::mode_t) -> core::ffi::c_int>,
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
    conntab: *mut std::collections::HashMap<Vec<u8>, *mut core::ffi::c_void>,
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

#[derive(Clone)]
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
    fn add_u64(&mut self, data: u64) {
        self.add_u32((data>>32) as u32);
        self.add_u32((data & 4294967295) as u32);
    }
    unsafe fn add_buf(&mut self, data: &mut Buffer_sys) {
		for idx in 0..data.len {
			self.p.push(*(data.p.offset(idx as isize)));
		}
    }
    fn add_str(&mut self, data: &[u8]) {
        self.add_u32(data.len() as u32);
        self.add(data);
    }
}

#[derive(Clone)]
#[repr(C)]
pub struct Conn {
    lock_write: libc::pthread_mutex_t,
    processing_thread_started: core::ffi::c_int,
    rfd: core::ffi::c_int,
    wfd: core::ffi::c_int,
    connver: core::ffi::c_int,
    req_count: core::ffi::c_int,
    dir_count: core::ffi::c_int,
    file_count: core::ffi::c_int,
}

struct DirHandle {
    buf: Buffer_sys,
    conn: *mut Conn,
}

type RequestFunc = unsafe extern "C" fn(&mut Request);

#[derive(Clone)]
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

#[derive(Clone)]
#[repr(C)]
pub struct SshfsIo {
	num_reps: core::ffi::c_int,
	finished: libc::pthread_cond_t,
	error: core::ffi::c_int,
}

#[derive(Clone)]
#[repr(C)]
struct List_head {
    prev: *mut List_head,
    next: *mut List_head,
}

#[derive(Clone)]
#[repr(C)]
pub struct SshfsFile {
    handle: Buffer_sys,
    write_reqs: List_head,
    write_finished: libc::pthread_cond_t,
    write_error: core::ffi::c_int,
    readahead: *mut core::ffi::c_void,
    next_pos: libc::off_t,
    is_seq: core::ffi::c_int,
    conn: *mut Conn,
    connver: core::ffi::c_int,
    modifver: core::ffi::c_int,
}

#[repr(C)]
struct ConntabEntry {
    refcount: core::ffi::c_uint,
    conn: *mut Conn,
}

#[no_mangle]
pub unsafe extern "C" fn req_table_new() -> *mut std::collections::HashMap<u32, *mut Request> {
    Box::into_raw(Box::default())
}

#[no_mangle]
pub unsafe extern "C" fn req_table_lookup(key: u32) -> *mut Request {
    let sshfs_ref = unsafe { retrieve_sshfs().unwrap() };
    let reqtab = unsafe { &(*sshfs_ref.reqtab) };
    match reqtab.get(&key) {
        Some(req) => *req,
        None => std::ptr::null_mut(),
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

type ClearReqFunc = extern "C" fn(*mut Request, *mut Conn) -> core::ffi::c_int;

#[no_mangle]
pub extern "C" fn req_table_foreach_remove(cfunc: ClearReqFunc, conn: *mut Conn) {
    let sshfs_ref = unsafe { retrieve_sshfs().unwrap() };
    let reqtab = unsafe { &(*sshfs_ref.reqtab) };
    let mut del_list = Vec::new();
    for (key, val) in reqtab.iter() {
        if cfunc(*val, conn) != 0 {
            del_list.push(key);
        }
    }
    let reqtab = unsafe { &mut (*sshfs_ref.reqtab) };
    for key in del_list {
        reqtab.remove(key);
    }
}

#[no_mangle]
pub unsafe extern "C" fn conn_table_new(
) -> *mut std::collections::HashMap<Vec<u8>, *mut core::ffi::c_void> {
    Box::into_raw(Box::default())
}

#[no_mangle]
pub unsafe extern "C" fn conn_table_lookup(
    key: *const core::ffi::c_char,
) -> *mut core::ffi::c_void {
    let key = unsafe { core::ffi::CStr::from_ptr(key) };
    let key_org = key.to_bytes();
    let mut key = Vec::new();
    for c in key_org.iter() {
        key.push(*c);
    }
    let sshfs_ref = unsafe { retrieve_sshfs().unwrap() };
    let conntab = unsafe { &(*sshfs_ref.conntab) };
    match conntab.get(&key) {
        Some(ce) => *ce,
        None => std::ptr::null_mut(),
    }
}

#[no_mangle]
fn conn_table_lookup_slice(key: &[u8]) -> *mut core::ffi::c_void {
    let key_org = key;
    let mut key = Vec::new();
    for c in key_org.iter() {
        key.push(*c);
    }
    let sshfs_ref = unsafe { retrieve_sshfs().unwrap() };
    let conntab = unsafe { &(*sshfs_ref.conntab) };
    match conntab.get(&key) {
        Some(ce) => *ce,
        None => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn conn_table_remove(key: *const core::ffi::c_char) {
    let key = unsafe { core::ffi::CStr::from_ptr(key) };
    let key_org = key.to_bytes();
    let mut key = Vec::new();
    for c in key_org.iter() {
        key.push(*c);
    }
    let sshfs_ref = unsafe { retrieve_sshfs().unwrap() };
    let conntab = unsafe { &mut (*sshfs_ref.conntab) };
    conntab.remove(&key);
}

#[no_mangle]
fn conn_table_remove_slice(key: &[u8]) {
    let key_org = key;
    let mut key = Vec::new();
    for c in key_org.iter() {
        key.push(*c);
    }
    let sshfs_ref = unsafe { retrieve_sshfs().unwrap() };
    let conntab = unsafe { &mut (*sshfs_ref.conntab) };
    conntab.remove(&key);
}

#[no_mangle]
pub unsafe extern "C" fn conn_table_insert(
    key: *const core::ffi::c_char,
    val: *mut core::ffi::c_void,
) {
    let key = unsafe { core::ffi::CStr::from_ptr(key) };
    let key_org = key.to_bytes();
    let mut key = Vec::new();
    for c in key_org.iter() {
        key.push(*c);
    }
    let sshfs_ref = unsafe { retrieve_sshfs().unwrap() };
    let conntab = unsafe { &mut (*sshfs_ref.conntab) };
    conntab.insert(key, val);
}

#[no_mangle]
fn conn_table_insert_slice(key: &[u8], val: *mut core::ffi::c_void) {
    let key_org = key;
    let mut key = Vec::new();
    for c in key_org.iter() {
        key.push(*c);
    }
    let sshfs_ref = unsafe { retrieve_sshfs().unwrap() };
    let conntab = unsafe { &mut (*sshfs_ref.conntab) };
    conntab.insert(key, val);
}

#[no_mangle]
pub unsafe extern "C" fn get_sshfs_file(fi: *const fuse_file_info) -> *mut SshfsFile {
    (*fi).fh as *mut SshfsFile
}

#[no_mangle]
pub unsafe extern "C" fn sshfs_file_is_conn(sf: *const SshfsFile) -> core::ffi::c_int {
    libc::pthread_mutex_lock(retrieve_sshfs().unwrap().lock_ptr);
    let ret = if (*sf).connver == (*((*sf).conn)).connver {
        1
    } else {
        0
    };
    libc::pthread_mutex_unlock(retrieve_sshfs().unwrap().lock_ptr);
    ret
}

#[no_mangle]
pub extern "C" fn sshfs_inc_modifver() {
    unsafe {
        libc::pthread_mutex_lock(retrieve_sshfs().unwrap().lock_ptr);
        retrieve_sshfs().unwrap().modifver += 1;
        libc::pthread_mutex_unlock(retrieve_sshfs().unwrap().lock_ptr);
    };
}

#[no_mangle]
pub unsafe extern "C" fn request_free(req: *mut Request) {
    let mut req = Box::from_raw(req);
    if let Some(func) = req.end_func {
        func(&mut req);
    }
    (*(req.conn)).req_count -= 1;
    libc::free(req.reply.p as *mut core::ffi::c_void);
    libc::sem_destroy(&mut req.ready as *mut libc::sem_t);
}

#[no_mangle]
pub extern "C" fn malloc_conn() -> *mut Conn {
    let conn_ptr = unsafe { libc::calloc(1, std::mem::size_of::<Conn>()) } as *mut Conn;
    if conn_ptr.is_null() {
        panic!("sshfs: memory allocation failed");
    };
    // Default が実装されていないため、一旦malloc したものをclone する
    let conn = std::sync::Arc::new(unsafe { (*conn_ptr).clone() });
    unsafe {
        libc::free(conn_ptr as *mut core::ffi::c_void);
    };
    std::sync::Arc::into_raw(conn) as *mut Conn
}

extern "C" {
    fn buf_get_uint32(buf: *mut core::ffi::c_void, cal: *mut u32) -> core::ffi::c_int;
    fn sftp_error_to_errno(errno: u32) -> core::ffi::c_int;
    fn get_conn(sshfs_file: *const core::ffi::c_void, path: *const core::ffi::c_void) -> *mut Conn;
    fn retrieve_sshfs() -> Option<&'static mut sshfs>;
    fn sftp_get_id() -> u32;
    fn iov_length(iov: *mut libc::iovec, nr_segs: core::ffi::c_ulong) -> usize;
    fn type_name(ssh_type: u8) -> *const core::ffi::c_char;
    fn sftp_send_iov(
        conn: *mut Conn,
        ssh_type: u8,
        id: u32,
        iov: *mut libc::iovec,
        count: usize,
    ) -> core::ffi::c_int;
    fn sftp_readdir_async(
        conn: *mut Conn,
        handle: &Buffer_sys,
        buf: *mut core::ffi::c_void,
        offset: libc::off_t,
        filler: *mut core::ffi::c_void,
    ) -> core::ffi::c_int;
    fn sshfs_async_read(
        sf: *mut SshfsFile,
        buf: *mut core::ffi::c_char,
        size: usize,
        offset: libc::off_t,
    ) -> core::ffi::c_int;
    fn sshfs_async_write(
        sf: *mut SshfsFile,
        buf: *mut core::ffi::c_char,
        size: usize,
        offset: libc::off_t,
    ) -> core::ffi::c_int;
    fn connect_remote(conn: *mut Conn) -> core::ffi::c_int;
    fn sftp_detect_uid(conn: *mut Conn);
    fn process_requests(data: *mut core::ffi::c_void) -> *mut core::ffi::c_void;
    fn buf_get_entries(
        buf: *mut Buffer_sys,
        dbuf: *mut core::ffi::c_void,
        filler: *mut core::ffi::c_void,
    ) -> core::ffi::c_int;
    fn list_empty(head: *const List_head) -> core::ffi::c_int;
    fn list_del(entry: *mut List_head);
    fn list_add(new: *mut List_head, head: *mut List_head);
    fn sshfs_send_read(
        sf: *mut SshfsFile,
        size: usize,
        offset: libc::off_t,
    ) -> *mut core::ffi::c_void;
    fn wait_chunk(
        chunk: *mut core::ffi::c_void,
        buf: *mut core::ffi::c_char,
        size: usize,
    ) -> core::ffi::c_int;
    fn cache_get_write_ctr() -> u64;
    fn list_init(head: *mut List_head);
    fn buf_to_iov(buf: *mut Buffer_sys, iov: *mut libc::iovec);
    fn buf_get_attrs(
        buf: *mut Buffer_sys,
        stbuf: *mut libc::stat,
        flagsp: *mut core::ffi::c_void,
    ) -> core::ffi::c_int;
    fn cache_add_attr(path: *const core::ffi::c_char, stbuf: *mut libc::stat, wrctr: u64);
    fn cache_invalidate(path: *const core::ffi::c_char);
    fn set_direct_io(fi: *mut fuse_file_info);
    fn sshfs_sync_write_begin(req: &mut Request);
    fn sshfs_sync_write_end(req: &mut Request);
}

fn get_real_path(path: &[u8]) -> Vec<u8> {
    let base_path = unsafe { retrieve_sshfs().unwrap().base_path };
    let mut real_path = Vec::new();
    if unsafe { *base_path } != 0 {
        let mut base_path_len = 0;
        while unsafe { *(base_path.offset(base_path_len)) } != 0 {
            real_path.push(unsafe { *(base_path.offset(base_path_len)) as u8 });
            base_path_len += 1;
        }
        if path.len() > 1 {
            if unsafe { *(base_path.offset(base_path_len - 1)) } != b'/' as core::ffi::c_char {
                real_path.push(b'/');
            }
            real_path.extend(&path[1..]);
        }
    } else if path.len() > 1 {
        real_path.extend(&path[1..]);
    } else {
        real_path.push(b'.');
    }
    real_path
}

#[no_mangle]
pub unsafe extern "C" fn start_processing_thread(conn: *mut Conn) -> core::ffi::c_int {
    if (*conn).processing_thread_started != 0 {
        0
    } else if (*conn).rfd == -1 && connect_remote(conn) != 0 {
        -libc::EIO
    } else {
        if retrieve_sshfs().unwrap().detect_uid != 0 {
            sftp_detect_uid(conn);
            retrieve_sshfs().unwrap().detect_uid = 0;
        }
        // 本来はスタックに持つものだが、未初期化の変数が使用できないためmalloc で確保している
        let newset = libc::malloc(std::mem::size_of::<libc::sigset_t>()) as *mut libc::sigset_t;
        let oldset = libc::malloc(std::mem::size_of::<libc::sigset_t>()) as *mut libc::sigset_t;
        libc::sigemptyset(newset);
        libc::sigaddset(newset, libc::SIGTERM);
        libc::sigaddset(newset, libc::SIGINT);
        libc::sigaddset(newset, libc::SIGHUP);
        libc::sigaddset(newset, libc::SIGQUIT);
        libc::pthread_sigmask(libc::SIG_BLOCK, newset, oldset);
        let conn_org = std::sync::Arc::from_raw(conn);
        let conn_clone = conn_org.clone();
        let conn = std::sync::Arc::into_raw(conn_org) as *mut Conn;
        let builder = std::thread::Builder::new();
        let handle = builder.spawn(move || {
            let conn_ptr = std::sync::Arc::into_raw(conn_clone);
            process_requests(conn_ptr as *mut core::ffi::c_void);
            std::sync::Arc::from_raw(conn_ptr)
        });
        if let Err(err) = handle {
            eprintln!("failed to create thread: {}", err.kind());
            libc::free(newset as *mut core::ffi::c_void);
            libc::free(oldset as *mut core::ffi::c_void);
            -libc::EIO
        } else {
            libc::pthread_sigmask(libc::SIG_BLOCK, oldset, std::ptr::null_mut());
            (*conn).processing_thread_started = 1;
            libc::free(newset as *mut core::ffi::c_void);
            libc::free(oldset as *mut core::ffi::c_void);
            0
        }
    }
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
        let err = unsafe {
            ((*(sshfs_ref.op)).getattr.unwrap())(path, Some(&mut (*stbuf)), std::ptr::null_mut())
        };
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
    req: Option<Box<Request>>,
    op_type: u8,
    expect_type: u8,
    outbuf: Option<&mut Buffer_sys>,
) -> core::ffi::c_int {
    let mut req = req.unwrap();
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
            if buf_get_uint32(
                &mut req.reply as *mut Buffer_sys as *mut core::ffi::c_void,
                &mut serr as *mut u32,
            ) != -1
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
                    _ => -sftp_error_to_errno(serr),
                }
            } else {
                -libc::EIO
            }
        } else {
            let outbuf = outbuf.unwrap();
            outbuf.p = libc::malloc(req.reply.size - req.reply.len) as *const u8;
            if outbuf.p == (std::ptr::null_mut() as *const u8) {
                panic!("sshfs: memory allocation failed");
            }
            outbuf.len = 0;
            outbuf.size = req.reply.size - req.reply.len;
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
    request_free(Box::into_raw(req));
    libc::pthread_mutex_unlock(retrieve_sshfs().unwrap().lock_ptr);
    err
}

#[no_mangle]
pub unsafe extern "C" fn sftp_request_send(
    conn: *mut Conn,
    ssh_type: u8,
    iov: *mut libc::iovec,
    count: usize,
    begin_func: Option<RequestFunc>,
    end_func: Option<RequestFunc>,
    want_reply: core::ffi::c_uint,
    data: *mut core::ffi::c_void,
    reqp: *mut *mut Request,
) -> core::ffi::c_int {
    let req_ptr = libc::calloc(1, std::mem::size_of::<Request>()) as *mut Request;
    // Default が実装されていないため、一旦malloc したものをclone する
    let mut req = Box::new((*req_ptr).clone());
    libc::free(req_ptr as *mut core::ffi::c_void);
    req.want_reply = want_reply;
    req.end_func = end_func;
    req.data = data;
    libc::sem_init(&mut (req.ready) as *mut libc::sem_t, 0, 0);
    req.reply.p = std::ptr::null();
    req.reply.len = 0;
    req.reply.size = 0;
    libc::pthread_mutex_lock(retrieve_sshfs().unwrap().lock_ptr);
    if let Some(func) = begin_func {
        func(&mut req);
    }
    let id = sftp_get_id();
    req.id = id;
    req.conn = conn;
    (*(req.conn)).req_count += 1;
    let mut err = start_processing_thread(conn);
    let req = Box::into_raw(req);
    if err != 0 {
        libc::pthread_mutex_unlock(retrieve_sshfs().unwrap().lock_ptr);
    } else {
        (*req).len = iov_length(iov, count.try_into().unwrap()) + 9;
        let sshfs_obj = retrieve_sshfs().unwrap();
        sshfs_obj.outstanding_len += <usize as TryInto<u32>>::try_into((*req).len).unwrap();
        while sshfs_obj.outstanding_len > sshfs_obj.max_outstanding_len {
            libc::pthread_cond_wait(
                &mut sshfs_obj.outstanding_cond as *mut libc::pthread_cond_t,
                sshfs_obj.lock_ptr,
            );
        }
        req_table_insert(id, req);
        if sshfs_obj.debug != 0 {
            libc::gettimeofday(
                &mut (*req).start as *mut libc::timeval,
                std::ptr::null_mut(),
            );
            sshfs_obj.num_sent += 1;
            sshfs_obj.bytes_sent += (*req).len as u64;
            eprintln!(
                "{0:<5} {1}",
                id,
                core::ffi::CStr::from_ptr(type_name(ssh_type))
                    .to_str()
                    .unwrap()
            );
        }
        libc::pthread_mutex_unlock(retrieve_sshfs().unwrap().lock_ptr);
        err = -libc::EIO;
        if sftp_send_iov(conn, ssh_type, id, iov, count) == -1 {
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
        sftp_request_wait(Some(Box::from_raw(req)), ssh_type, 0, None);
    } else {
        *reqp = req;
    }
    err
}

#[no_mangle]
pub unsafe extern "C" fn sftp_request(
    conn: *mut Conn,
    ssh_type: u8,
    buf: *const Buffer_sys,
    expect_type: u8,
    outbuf: Option<&mut Buffer_sys>,
) -> core::ffi::c_int {
    // 本来はスタックに持つものだが、未初期化の変数が使用できないためmalloc で確保している
    let iov = libc::malloc(std::mem::size_of::<libc::iovec>()) as *mut libc::iovec;
    let reqp = libc::malloc(std::mem::size_of::<*mut Request>()) as *mut *mut Request;
    (*iov).iov_base = (*buf).p as *mut core::ffi::c_void;
    (*iov).iov_len = (*buf).len;
    let ret = sftp_request_send(
        conn,
        ssh_type,
        iov,
        1,
        None,
        None,
        expect_type as core::ffi::c_uint,
        std::ptr::null_mut(),
        reqp,
    );
    let ret = if expect_type == 0 {
        ret
    } else {
        sftp_request_wait(Some(Box::from_raw(*reqp)), ssh_type, expect_type, outbuf)
    };
    libc::free(iov as *mut core::ffi::c_void);
    libc::free(reqp as *mut core::ffi::c_void);
    ret
}

#[no_mangle]
pub unsafe extern "C" fn sftp_readdir_sync(
    conn: *mut Conn,
    handle: &Buffer_sys,
    buf: *mut core::ffi::c_void,
    offset: libc::off_t,
    filler: *mut core::ffi::c_void,
) -> core::ffi::c_int {
    assert_eq!(0, offset);
    let mut err = 0;
    while err == 0 {
        let name = unsafe { libc::malloc(std::mem::size_of::<Buffer_sys>()) } as *mut Buffer_sys;
        err = unsafe {
            sftp_request(
                conn,
                SSH_FXP_READDIR,
                handle,
                SSH_FXP_NAME,
                Some(&mut (*name)),
            )
        };
        if err == 0 {
            unsafe { buf_get_entries(name, buf, filler) };
            unsafe { libc::free((*name).p as *mut core::ffi::c_void) };
        }
        unsafe { libc::free(name as *mut core::ffi::c_void) };
    }
    if err == MY_EOF {
        0
    } else {
        err
    }
}

#[no_mangle]
pub unsafe extern "C" fn sshfs_opendir(
    path: *const core::ffi::c_char,
    fi: &mut fuse_file_info,
) -> core::ffi::c_int {
    let path = unsafe { core::ffi::CStr::from_ptr(path) }.to_bytes();
    let path = get_real_path(path);
    let mut buf = Buffer::new(0);
    buf.add_str(&path);
    let buf = unsafe { buf.translate_into_sys() };
    let mut handle = Box::new(DirHandle {
        buf: Buffer_sys {
            p: std::ptr::null(),
            len: 0,
            size: 0,
        },
        conn: std::ptr::null_mut(),
    });
    handle.conn = unsafe { get_conn(std::ptr::null_mut(), std::ptr::null_mut()) };
    let err = unsafe {
        sftp_request(
            handle.conn,
            SSH_FXP_OPENDIR,
            &buf,
            SSH_FXP_HANDLE,
            Some(&mut handle.buf),
        )
    };
    if err == 0 {
        handle.buf.len = handle.buf.size;
        unsafe {
            libc::pthread_mutex_lock(retrieve_sshfs().unwrap().lock_ptr);
            (*(handle.conn)).dir_count += 1;
            libc::pthread_mutex_unlock(retrieve_sshfs().unwrap().lock_ptr);
        }
        fi.fh = Box::into_raw(handle) as u64;
    }
    err
}

#[no_mangle]
pub unsafe extern "C" fn sshfs_readdir(
    _path: *const core::ffi::c_char,
    dbuf: *mut core::ffi::c_void,
    filler: *mut core::ffi::c_void,
    offset: libc::off_t,
    fi: &mut fuse_file_info,
    _flag: i32,
) -> core::ffi::c_int {
    let handle = fi.fh as *mut DirHandle;
    if retrieve_sshfs().unwrap().sync_readdir != 0 {
        sftp_readdir_sync((*handle).conn, &(*handle).buf, dbuf, offset, filler)
    } else {
        sftp_readdir_async((*handle).conn, &(*handle).buf, dbuf, offset, filler)
    }
}

#[no_mangle]
pub unsafe extern "C" fn sshfs_releasedir(
    _path: *const core::ffi::c_char,
    fi: &mut fuse_file_info,
) -> core::ffi::c_int {
    let handle = Box::from_raw(fi.fh as *mut DirHandle);
    let err = sftp_request(handle.conn, SSH_FXP_CLOSE, &handle.buf, 0, None);
    libc::pthread_mutex_lock(retrieve_sshfs().unwrap().lock_ptr);
    (*(handle.conn)).dir_count -= 1;
    libc::pthread_mutex_unlock(retrieve_sshfs().unwrap().lock_ptr);
    libc::free(handle.buf.p as *mut core::ffi::c_void);
    err
}

#[no_mangle]
pub unsafe extern "C" fn sshfs_mkdir(
    path: *const core::ffi::c_char,
    mode: libc::mode_t,
) -> core::ffi::c_int {
    let real_path = unsafe { core::ffi::CStr::from_ptr(path) }.to_bytes();
    let real_path = get_real_path(real_path);
    let mut buf = Buffer::new(0);
    buf.add_str(&real_path);
    buf.add_u32(SSH_FILEXFER_ATTR_PERMISSIONS);
    buf.add_u32(mode);
    let buf = unsafe { buf.translate_into_sys() };
    let err = unsafe {
        sftp_request(
            get_conn(std::ptr::null_mut(), std::ptr::null_mut()),
            SSH_FXP_MKDIR,
            &buf,
            SSH_FXP_STATUS,
            None,
        )
    };
    if err == -libc::EPERM
        && unsafe {
            ((*(retrieve_sshfs().unwrap().op)).access.unwrap())(
                path,
                libc::R_OK.try_into().unwrap(),
            )
        } == 0
    {
        -libc::EEXIST
    } else {
        err
    }
}

fn sshfs_unlink_body(path: &[u8]) -> core::ffi::c_int {
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
pub unsafe extern "C" fn sshfs_unlink(path: *const core::ffi::c_char) -> core::ffi::c_int {
    let path = core::ffi::CStr::from_ptr(path).to_bytes();
    sshfs_unlink_body(path)
}

#[no_mangle]
pub unsafe extern "C" fn sshfs_rmdir(path: *const core::ffi::c_char) -> core::ffi::c_int {
    let path = unsafe { core::ffi::CStr::from_ptr(path) }.to_bytes();
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

fn sshfs_do_rename(from_path: &[u8], to_path: &[u8]) -> core::ffi::c_int {
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

fn sshfs_ext_posix_rename(from_path: &[u8], to_path: &[u8]) -> core::ffi::c_int {
    let from_path = get_real_path(from_path);
    let to_path = get_real_path(to_path);
    let mut buf = Buffer::new(0);
    buf.add_str(SFTP_EXT_POSIX_RENAME.as_bytes());
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
}

fn random_string(s: &mut Vec<u8>, length: core::ffi::c_int) {
    for _idx in 0..length {
        s.push(b'0' + rand::thread_rng().gen_range(0..10) as u8);
    }
}

fn sshfs_rename_body(
    from_path: &[u8],
    to_path: &[u8],
    flags: core::ffi::c_uint,
    sshfs_ref: &mut sshfs,
) -> core::ffi::c_int {
    if flags != 0 {
        -libc::EINVAL
    } else {
        let mut err = if sshfs_ref.ext_posix_rename != 0 {
            sshfs_ext_posix_rename(from_path, to_path)
        } else {
            sshfs_do_rename(from_path, to_path)
        };
        if err == -libc::EPERM
            && sshfs_ref.rename_workaround != 0
            && to_path.len() as core::ffi::c_int + RENAME_TEMP_CHARS < libc::PATH_MAX
        {
            let mut totmp = Vec::with_capacity(libc::PATH_MAX as usize);
            totmp.extend(to_path);
            random_string(&mut totmp, RENAME_TEMP_CHARS);
            if sshfs_do_rename(to_path, &totmp) == 0 {
                err = sshfs_do_rename(from_path, to_path);
                if err == 0 {
                    err = sshfs_unlink_body(&totmp);
                } else {
                    sshfs_do_rename(&totmp, to_path);
                }
            }
        }
        if err == -libc::EPERM && sshfs_ref.rename_workaround != 0 {
            err = -libc::EXDEV;
        }
        if err == 0 && sshfs_ref.max_conns > 1 {
            unsafe {
                libc::pthread_mutex_lock(sshfs_ref.lock_ptr);
                let ce = conn_table_lookup_slice(from_path);
                if !ce.is_null() {
                    conn_table_insert_slice(to_path, ce);
                    conn_table_remove_slice(from_path);
                }
                libc::pthread_mutex_unlock(sshfs_ref.lock_ptr);
            }
        }
        err
    }
}

#[no_mangle]
pub unsafe extern "C" fn sshfs_rename(
    from_path: *const core::ffi::c_char,
    to_path: *const core::ffi::c_char,
    flags: core::ffi::c_uint,
) -> core::ffi::c_int {
    let from_path = core::ffi::CStr::from_ptr(from_path).to_bytes();
    let to_path = core::ffi::CStr::from_ptr(to_path).to_bytes();
    let sshfs_ref = retrieve_sshfs().unwrap();
    sshfs_rename_body(from_path, to_path, flags, sshfs_ref)
}

#[no_mangle]
pub unsafe extern "C" fn sshfs_link(
    from_path: *const core::ffi::c_char,
    to_path: *const core::ffi::c_char,
) -> core::ffi::c_int {
    let sshfs_ref = unsafe { retrieve_sshfs().unwrap() };

    if sshfs_ref.ext_hardlink != 0 && sshfs_ref.disable_hardlink == 0 {
        let from_path = unsafe { core::ffi::CStr::from_ptr(from_path) }.to_bytes();
        let from_path = get_real_path(from_path);
        let to_path = unsafe { core::ffi::CStr::from_ptr(to_path) }.to_bytes();
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

unsafe fn sshfs_sync_read(
    sf: *mut SshfsFile,
    buf: *mut core::ffi::c_char,
    size: usize,
    offset: libc::off_t,
) -> core::ffi::c_int {
    wait_chunk(sshfs_send_read(sf, size, offset), buf, size)
}

#[no_mangle]
pub unsafe extern "C" fn free_sf(sf: *mut SshfsFile) {
    let _ = Box::from_raw(sf);
}

#[no_mangle]
pub unsafe extern "C" fn sshfs_open_common(
    path: *const core::ffi::c_char,
    mode: libc::mode_t,
    fi: *mut fuse_file_info,
) -> core::ffi::c_int {
    let sshfs_ref = retrieve_sshfs().unwrap();
    let wrctr = if sshfs_ref.dir_cache != 0 {
        cache_get_write_ctr()
    } else {
        0
    };

    if sshfs_ref.direct_io != 0 {
        set_direct_io(fi);
    }

    let mut pflags = match (*fi).flags & libc::O_ACCMODE {
        flags if flags == libc::O_RDONLY => SSH_FXF_READ,
        flags if flags == libc::O_WRONLY => SSH_FXF_WRITE,
        flags if flags == libc::O_RDWR => SSH_FXF_READ | SSH_FXF_WRITE,
        _ => return -libc::EINVAL,
    };

    if ((*fi).flags & libc::O_CREAT) != 0 {
        pflags |= SSH_FXF_CREAT;
    }
    if ((*fi).flags & libc::O_EXCL) != 0 {
        pflags |= SSH_FXF_EXCL;
    }
    if ((*fi).flags & libc::O_TRUNC) != 0 {
        pflags |= SSH_FXF_TRUNC;
    }
    if ((*fi).flags & libc::O_APPEND) != 0 {
        pflags |= SSH_FXF_APPEND;
    }

    let sf_malloc = libc::calloc(1, std::mem::size_of::<SshfsFile>()) as *mut SshfsFile;
    let mut sf = Box::new((*sf_malloc).clone());
    libc::free(sf_malloc as *mut core::ffi::c_void);
    list_init(&mut (sf.write_reqs) as *mut List_head);
    libc::pthread_cond_init(
        &mut (sf.write_finished) as *mut libc::pthread_cond_t,
        std::ptr::null_mut(),
    );
    sf.is_seq = 0;
    sf.next_pos = 0;
    libc::pthread_mutex_lock(sshfs_ref.lock_ptr);
    sf.modifver = sshfs_ref.modifver as core::ffi::c_int;
    let ce = if sshfs_ref.max_conns > 1 {
        let mut ret = conn_table_lookup(path) as *mut ConntabEntry;
        if ret.is_null() {
            ret = libc::malloc(std::mem::size_of::<ConntabEntry>()) as *mut ConntabEntry;
            (*ret).refcount = 0;
            (*ret).conn = get_conn(std::ptr::null_mut(), std::ptr::null_mut());
            conn_table_insert(path, ret as *mut core::ffi::c_void);
        }
        sf.conn = (*ret).conn;
        (*ret).refcount += 1;
        (*(sf.conn)).file_count += 1;
        assert!((*(sf.conn)).file_count > 0);
        ret
    } else {
        sf.conn = *(sshfs_ref.conns as *mut *mut Conn);
        std::ptr::null_mut()
    };
    sf.connver = (*(sf.conn)).connver;
    libc::pthread_mutex_unlock(sshfs_ref.lock_ptr);
    let mut openreq: *mut Request = std::ptr::null_mut();
    // 本来はスタックに持つものだが、未初期化の変数が使用できないためmalloc で確保している
    let iov = libc::malloc(std::mem::size_of::<libc::iovec>()) as *mut libc::iovec;
    let stbuf = libc::malloc(std::mem::size_of::<libc::stat>()) as *mut libc::stat;
    let mut buf = Buffer::new(0);
    let path_org = path;
    let path = unsafe { core::ffi::CStr::from_ptr(path) }.to_bytes();
    let path = get_real_path(path);
    buf.add_str(&path);
    buf.add_u32(pflags);
    buf.add_u32(SSH_FILEXFER_ATTR_PERMISSIONS);
    buf.add_u32(mode);
    let mut buf = unsafe { buf.translate_into_sys() };
    buf_to_iov(&mut buf as *mut Buffer_sys, iov);
    sftp_request_send(
        sf.conn,
        SSH_FXP_OPEN,
        iov,
        1,
        None,
        None,
        1,
        std::ptr::null_mut(),
        &mut openreq as *mut *mut Request,
    );
    let mut buf = Buffer::new(0);
    buf.add_str(&path);
    let buf = unsafe { buf.translate_into_sys() };
    let ssh_type = if sshfs_ref.follow_symlinks != 0 {
        SSH_FXP_STAT
    } else {
        SSH_FXP_LSTAT
    };
    // 本来はスタックに持つものだが、未初期化の変数が使用できないためmalloc で確保している
    let outbuf = libc::malloc(std::mem::size_of::<Buffer_sys>()) as *mut Buffer_sys;
    let mut err2 = sftp_request(
        sf.conn,
        ssh_type,
        &buf,
        SSH_FXP_ATTRS,
        Some(&mut (*outbuf)),
    );
    if err2 == 0 {
        err2 = buf_get_attrs(outbuf, stbuf, std::ptr::null_mut());
        libc::free((*outbuf).p as *mut core::ffi::c_void);
    }
    libc::free(outbuf as *mut core::ffi::c_void);
    let mut err = sftp_request_wait(
        Some(Box::from_raw(openreq)),
        SSH_FXP_OPEN,
        SSH_FXP_HANDLE,
        Some(&mut sf.handle),
    );
    if err == 0 && err2 != 0 {
        sf.handle.len = sf.handle.size;
        sftp_request(sf.conn, SSH_FXP_CLOSE, &sf.handle, 0, None);
        libc::free(sf.handle.p as *mut core::ffi::c_void);
        err = err2;
    }
    if err == 0 {
        if sshfs_ref.dir_cache != 0 {
            cache_add_attr(path_org, stbuf, wrctr);
        }
        sf.handle.len = sf.handle.size;
        (*fi).fh = Box::into_raw(sf) as u64;
    } else {
        if sshfs_ref.dir_cache != 0 {
            cache_invalidate(path_org);
        }
        if sshfs_ref.max_conns > 1 {
            libc::pthread_mutex_lock(sshfs_ref.lock_ptr);
            (*(sf.conn)).file_count -= 1;
            (*ce).refcount -= 1;
            if (*ce).refcount == 0 {
                conn_table_remove(path_org);
                libc::free(ce as *mut core::ffi::c_void);
            }
            libc::pthread_mutex_unlock(sshfs_ref.lock_ptr);
        }
    }
    libc::free(stbuf as *mut core::ffi::c_void);
    libc::free(iov as *mut core::ffi::c_void);
    err
}

#[no_mangle]
pub unsafe extern "C" fn sshfs_open(
    path: *const core::ffi::c_char,
    fi: *mut fuse_file_info,
) -> core::ffi::c_int {
    sshfs_open_common(path, 0, fi)
}

#[no_mangle]
pub unsafe extern "C" fn sshfs_flush(
    _path: *const core::ffi::c_char,
    fi: *mut fuse_file_info,
) -> core::ffi::c_int {
    let sf = get_sshfs_file(fi);
    if sshfs_file_is_conn(sf) == 0 {
        -libc::EIO
    } else if retrieve_sshfs().unwrap().sync_write != 0 {
        0
    } else {
        libc::pthread_mutex_lock(retrieve_sshfs().unwrap().lock_ptr);
        if list_empty(&((*sf).write_reqs) as *const List_head) == 0 {
			let curr_list = (*sf).write_reqs.prev;
			list_del(&mut ((*sf).write_reqs) as *mut List_head);
			list_init(&mut ((*sf).write_reqs) as *mut List_head);
			let mut write_reps = List_head {
				prev: std::ptr::null_mut() as *mut List_head,
				next: std::ptr::null_mut() as *mut List_head,
			};
			list_add(&mut write_reps as *mut List_head, curr_list);
			while list_empty(&write_reps as *const List_head) == 0 {
				libc::pthread_cond_wait(&mut ((*sf).write_finished) as *mut libc::pthread_cond_t, retrieve_sshfs().unwrap().lock_ptr);
			}
		}
        let err = (*sf).write_error;
        (*sf).write_error = 0;
        libc::pthread_mutex_unlock(retrieve_sshfs().unwrap().lock_ptr);
        err
    }
}

#[no_mangle]
pub unsafe extern "C" fn sshfs_read(
    _path: *const core::ffi::c_char,
    rbuf: *mut core::ffi::c_char,
    size: usize,
    offset: libc::off_t,
    fi: &mut fuse_file_info,
) -> core::ffi::c_int {
    let sf = get_sshfs_file(fi);
    if sshfs_file_is_conn(sf) == 0 {
        -libc::EIO
    } else if retrieve_sshfs().unwrap().sync_read != 0 {
        sshfs_sync_read(sf, rbuf, size, offset)
    } else {
        sshfs_async_read(sf, rbuf, size, offset)
    }
}

unsafe fn sshfs_sync_write(sf: *mut SshfsFile, mut wbuf: *mut core::ffi::c_char, mut size: usize,
                           mut offset: libc::off_t) -> core::ffi::c_int {
	let mut err = 0;
	let sshfs_ref = retrieve_sshfs().unwrap();
    let handle = &mut (*sf).handle;
    // 本来はスタックに持つものだが、未初期化の変数が使用できないためmalloc で確保している
    let sio = libc::malloc(std::mem::size_of::<SshfsIo>()) as *mut SshfsIo;
    (*sio).num_reps = 0;
    (*sio).error = 0;
    libc::pthread_cond_init(&mut (*sio).finished as *mut libc::pthread_cond_t, std::ptr::null());
    while err == 0 && size > 0 {
		let bsize = if size < sshfs_ref.max_write as usize {
			size
		} else {
			sshfs_ref.max_write as usize
		};
        let mut buf = Buffer::new(0);
        buf.add_buf(handle);
	    buf.add_u64(offset as u64);
	    buf.add_u32(bsize as u32);
        let buf = unsafe { buf.translate_into_sys() };
        // 本来はスタックに持つものだが、未初期化の変数が使用できないためmalloc で確保している
        let iov = libc::malloc(std::mem::size_of::<libc::iovec>()*2) as *mut libc::iovec;
        let iov0 = iov;
        let iov1 = iov.offset(1);
        (*iov0).iov_base = buf.p as *mut core::ffi::c_void;
        (*iov0).iov_len = buf.len;
        (*iov1).iov_base = wbuf as *mut core::ffi::c_void;
        (*iov1).iov_len = bsize;
        err = sftp_request_send((*sf).conn, SSH_FXP_WRITE, iov, 2,
					Some(sshfs_sync_write_begin),
					Some(sshfs_sync_write_end),
					0, sio as *mut core::ffi::c_void, std::ptr::null_mut());
		size -= bsize;
		wbuf = wbuf.offset(bsize as isize);
		offset += bsize as i64;
        libc::free(iov0 as *mut core::ffi::c_void);
        libc::free(iov1 as *mut core::ffi::c_void);
    }
    libc::pthread_mutex_lock(retrieve_sshfs().unwrap().lock_ptr);
    while (*sio).num_reps != 0 {
		libc::pthread_cond_wait(&mut (*sio).finished as *mut libc::pthread_cond_t, sshfs_ref.lock_ptr);
    }
    libc::pthread_mutex_unlock(retrieve_sshfs().unwrap().lock_ptr);
    if err == 0 {
		err = (*sio).error;
    }
    libc::free(sio as *mut core::ffi::c_void);
    err
}

#[no_mangle]
pub unsafe extern "C" fn sshfs_write(
    _path: *const core::ffi::c_char,
    wbuf: *mut core::ffi::c_char,
    size: usize,
    offset: libc::off_t,
    fi: &mut fuse_file_info,
) -> core::ffi::c_int {
    let sf = get_sshfs_file(fi);
    if sshfs_file_is_conn(sf) == 0 {
        -libc::EIO
    } else {
        sshfs_inc_modifver();
        let ret = if retrieve_sshfs().unwrap().sync_write != 0 && (*sf).write_error == 0 {
            sshfs_sync_write(sf, wbuf, size, offset)
        } else {
            sshfs_async_write(sf, wbuf, size, offset)
        };
        if ret == 0 {
            size as core::ffi::c_int
        } else {
            ret
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn sshfs_create(
    path: *const core::ffi::c_char,
    mode: libc::mode_t,
    fi: *mut fuse_file_info,
) -> core::ffi::c_int {
	let mode = if retrieve_sshfs().unwrap().createmode_workaround != 0 {
		0
	} else {
		mode
	};
    sshfs_open_common(path, mode, fi)
}
