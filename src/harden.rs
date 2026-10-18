//! Best-effort process and memory hardening for the time secrets are held.
//!
//! - No core dumps: a crash must not write the master key to disk.
//! - Linux: not dumpable, so other processes of the same user cannot ptrace it.
//! - Secret buffers are `mlock`ed so they are never swapped to disk, and zeroed on drop.
//!
//! Every step is best effort: failure is reported once and never blocks the user.

use zeroize::Zeroize;

/// Call once at startup, before any secret is read.
pub fn harden_process() -> Vec<&'static str> {
    let mut failed = Vec::new();
    #[cfg(unix)]
    {
        let zero = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        // SAFETY: setrlimit only reads the struct we pass.
        if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &zero) } != 0 {
            failed.push("コアダンプの無効化");
        }
    }
    #[cfg(target_os = "linux")]
    {
        // SAFETY: PR_SET_DUMPABLE takes plain integer arguments.
        if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
            failed.push("デバッガからの読み取り防止");
        }
    }
    failed
}

/// Pins `len` bytes at `ptr` in RAM. Returns false if the OS refused.
fn lock(ptr: *const u8, len: usize) -> bool {
    #[cfg(unix)]
    {
        // SAFETY: the range belongs to a live allocation owned by the caller.
        unsafe { libc::mlock(ptr.cast(), len) == 0 }
    }
    #[cfg(not(unix))]
    {
        let _ = (ptr, len);
        false
    }
}

fn unlock(ptr: *const u8, len: usize) {
    #[cfg(unix)]
    // SAFETY: same range that `lock` pinned.
    unsafe {
        libc::munlock(ptr.cast(), len);
    }
    #[cfg(not(unix))]
    let _ = (ptr, len);
}

/// A heap value with a stable address that stays in RAM and is zeroed on drop.
pub struct Locked<T: Zeroize> {
    inner: Box<T>,
    locked: bool,
}

impl<T: Zeroize> Locked<T> {
    pub fn new(value: T) -> Self {
        let inner = Box::new(value);
        let locked = lock((&*inner as *const T).cast(), std::mem::size_of::<T>());
        Self { inner, locked }
    }
    pub fn is_locked(&self) -> bool {
        self.locked
    }
}

impl<T: Zeroize> std::ops::Deref for Locked<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.inner
    }
}

impl<T: Zeroize> Drop for Locked<T> {
    fn drop(&mut self) {
        self.inner.zeroize();
        if self.locked {
            unlock((&*self.inner as *const T).cast(), std::mem::size_of::<T>());
        }
    }
}

/// A secret string whose heap buffer is pinned in RAM and zeroed on drop.
pub struct LockedString {
    text: String,
    locked: bool,
}

impl LockedString {
    pub fn new(text: String) -> Self {
        let locked = text.capacity() > 0 && lock(text.as_ptr(), text.capacity());
        Self { text, locked }
    }
}

impl std::ops::Deref for LockedString {
    type Target = str;
    fn deref(&self) -> &str {
        &self.text
    }
}

impl Drop for LockedString {
    fn drop(&mut self) {
        let (ptr, cap) = (self.text.as_ptr(), self.text.capacity());
        self.text.zeroize();
        if self.locked {
            unlock(ptr, cap);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_survive_locking_and_core_dumps_are_disabled() {
        assert!(harden_process().is_empty());
        let key = Locked::new([7u8; 32]);
        assert_eq!(*key, [7u8; 32]);
        let secret = LockedString::new("a long master secret".to_string());
        assert_eq!(&*secret, "a long master secret");
        #[cfg(unix)]
        {
            let mut limit = libc::rlimit { rlim_cur: 1, rlim_max: 1 };
            // SAFETY: getrlimit writes into the struct we own.
            unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut limit) };
            assert_eq!(limit.rlim_cur, 0);
        }
    }
}
