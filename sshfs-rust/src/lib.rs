const SSH_FXP_READ: u8 = 5;
const SSH_FXP_READDIR: u8 = 12;
const SSH_FXP_REMOVE: u8 = 13;
const SSH_FXP_RMDIR: u8 = 15;
const SSH_FXP_STATUS: u8 = 101;

const SSH_FX_OK: u32 = 0;
const SSH_FX_EOF: u32 = 1;
const SSH_FX_FAILURE: u32 = 4;

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

extern "C" {
    fn sshfs_base_path() -> *const core::ffi::c_char;
    fn sshfs_lock_ptr() -> *mut core::ffi::c_void;
}
