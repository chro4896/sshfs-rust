const SSH_FXP_READ: u8 = 5;
const SSH_FXP_READDIR: u8 = 12;
const SSH_FXP_REMOVE: u8 = 13;
const SSH_FXP_RMDIR: u8 = 15;
const SSH_FXP_STATUS: u8 = 101;

const SSH_FX_OK: u32 = 0;
const SSH_FX_EOF: u32 = 1;
const SSH_FX_FAILURE: u32 = 4;

const MY_EOF: core::ffi::c_int = 1;

extern "C" {
    fn sshfs_base_path() -> *const core::ffi::c_char;
    fn sshfs_lock_ptr() -> *mut core::ffi::c_void;
}
