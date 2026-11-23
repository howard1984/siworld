//! SIWORLD's pinned RandomX primitive and branch-dependent key schedule.

use std::{
    ffi::{c_uint, c_ulong, c_void},
    ptr::{self, NonNull},
    thread,
};

pub type Digest = [u8; 32];
pub use siworld_core::pow::{
    RANDOMX_ALGORITHM as ALGORITHM, RANDOMX_ARGON_SALT as ARGON_SALT,
    RANDOMX_INPUT_DOMAIN as INPUT_DOMAIN, RANDOMX_KEY_DELAY as KEY_DELAY,
    RANDOMX_KEY_INTERVAL as KEY_INTERVAL, randomx_epoch_key as epoch_key,
    randomx_key_height as key_height,
};

pub const CACHE_BYTES: u64 = 256 * 1024 * 1024;
pub const DATASET_BYTES: u64 = 2_181_038_016;
const FULL_MEM: c_uint = 4;
const JIT: c_uint = 8;
const SECURE: c_uint = 16;

pub fn header_input(header_seed: Digest, nonce: u64) -> [u8; INPUT_DOMAIN.len() + 40] {
    let mut input = [0; INPUT_DOMAIN.len() + 40];
    let prefix = INPUT_DOMAIN.len();
    input[..prefix].copy_from_slice(INPUT_DOMAIN);
    input[prefix..prefix + 32].copy_from_slice(&header_seed);
    input[prefix + 32..].copy_from_slice(&nonce.to_le_bytes());
    input
}

#[repr(C)]
struct CacheHandle([u8; 0]);
#[repr(C)]
struct DatasetHandle([u8; 0]);
#[repr(C)]
struct VmHandle([u8; 0]);

unsafe extern "C" {
    fn randomx_get_flags() -> c_uint;
    fn randomx_alloc_cache(flags: c_uint) -> *mut CacheHandle;
    fn randomx_init_cache(cache: *mut CacheHandle, key: *const c_void, size: usize);
    fn randomx_release_cache(cache: *mut CacheHandle);
    fn randomx_alloc_dataset(flags: c_uint) -> *mut DatasetHandle;
    fn randomx_dataset_item_count() -> c_ulong;
    fn randomx_init_dataset(
        dataset: *mut DatasetHandle,
        cache: *mut CacheHandle,
        start: c_ulong,
        count: c_ulong,
    );
    fn randomx_release_dataset(dataset: *mut DatasetHandle);
    fn randomx_create_vm(
        flags: c_uint,
        cache: *mut CacheHandle,
        dataset: *mut DatasetHandle,
    ) -> *mut VmHandle;
    fn randomx_destroy_vm(vm: *mut VmHandle);
    fn randomx_calculate_hash(
        vm: *mut VmHandle,
        input: *const c_void,
        size: usize,
        output: *mut c_void,
    );
}

#[derive(Clone, Copy)]
pub enum Implementation {
    Portable,
    Hardware,
}
impl Implementation {
    fn flags(self) -> c_uint {
        match self {
            Self::Portable => 0,
            // SAFETY: This is the library's read-only hardware query.
            Self::Hardware => unsafe { randomx_get_flags() },
        }
    }
}

pub struct Cache(NonNull<CacheHandle>, c_uint);

// SAFETY: Ownership is unique. Initialized caches are immutable and RandomX
// permits separate VMs and disjoint dataset fills to share a cache.
unsafe impl Send for Cache {}
unsafe impl Sync for Cache {}

impl Cache {
    pub fn new(key: &[u8], implementation: Implementation) -> Result<Self, &'static str> {
        let flags = implementation.flags();
        // SAFETY: The library owns the fresh allocation. It is initialized
        // exactly once with key bytes live until the synchronous call returns.
        let cache = NonNull::new(unsafe { randomx_alloc_cache(flags) })
            .ok_or("RandomX cache allocation failed")?;
        unsafe { randomx_init_cache(cache.as_ptr(), key.as_ptr().cast(), key.len()) };
        Ok(Self(cache, flags))
    }

    pub fn vm(&self) -> Result<Vm<'_>, &'static str> {
        Vm::create(self.1, Some(self), None)
    }
}

impl Drop for Cache {
    fn drop(&mut self) {
        // SAFETY: The unique allocation remains live until all VM borrows end.
        unsafe { randomx_release_cache(self.0.as_ptr()) };
    }
}

pub struct Dataset(NonNull<DatasetHandle>, c_uint);

// SAFETY: Dataset construction exposes only disjoint initialization ranges
// to workers; creation joins all workers before sharing a read-only dataset.
unsafe impl Send for Dataset {}
unsafe impl Sync for Dataset {}

impl Dataset {
    pub fn new(cache: &Cache, workers: usize) -> Result<Self, &'static str> {
        if !(1..=256).contains(&workers) {
            return Err("RandomX dataset worker count invalid");
        }
        // SAFETY: Default allocation has no platform-specific page requirement.
        let raw = NonNull::new(unsafe { randomx_alloc_dataset(0) })
            .ok_or("RandomX dataset allocation failed")?;
        let dataset = Self(raw, cache.1);
        // SAFETY: The upstream item count is a constant independent of input.
        #[allow(clippy::unnecessary_cast)] // c_ulong is 32 bits on Windows.
        let len = unsafe { randomx_dataset_item_count() } as u64;
        if len != DATASET_BYTES / 64 {
            return Err("RandomX dataset length differs from pinned parameters");
        }
        thread::scope(|scope| {
            let workers = workers as u64;
            for worker in 0..workers {
                let dataset = &dataset;
                let first = len * worker / workers;
                let end = len * (worker + 1) / workers;
                thread::Builder::new()
                    .spawn_scoped(scope, move || {
                        // SAFETY: The ranges partition the allocation without
                        // overlap, the cache stays live, and scope joins all fills.
                        dataset.init_range(cache, first as c_ulong, (end - first) as c_ulong);
                    })
                    .map_err(|_| "RandomX dataset worker unavailable")?;
            }
            Ok::<_, &'static str>(())
        })?;
        Ok(dataset)
    }

    fn init_range(&self, cache: &Cache, start: c_ulong, count: c_ulong) {
        unsafe { randomx_init_dataset(self.0.as_ptr(), cache.0.as_ptr(), start, count) };
    }

    pub fn vm(&self) -> Result<Vm<'_>, &'static str> {
        Vm::create(self.1 | FULL_MEM, None, Some(self))
    }
}

impl Drop for Dataset {
    fn drop(&mut self) {
        // SAFETY: The unique allocation remains live until all VM borrows end.
        unsafe { randomx_release_dataset(self.0.as_ptr()) };
    }
}

pub struct Vm<'a> {
    raw: NonNull<VmHandle>,
    _cache: Option<&'a Cache>,
    _dataset: Option<&'a Dataset>,
}

impl<'a> Vm<'a> {
    fn create(
        flags: c_uint,
        cache: Option<&'a Cache>,
        dataset: Option<&'a Dataset>,
    ) -> Result<Self, &'static str> {
        let flags = if flags & JIT != 0 {
            flags | SECURE
        } else {
            flags
        };
        // SAFETY: Borrowed owners were fully initialized and supply exactly the
        // mode's required pointer. The VM retains those borrows for its lifetime.
        let raw = NonNull::new(unsafe {
            randomx_create_vm(
                flags,
                cache.map_or(ptr::null_mut(), |value| value.0.as_ptr()),
                dataset.map_or(ptr::null_mut(), |value| value.0.as_ptr()),
            )
        })
        .ok_or("RandomX virtual machine unavailable")?;
        Ok(Self {
            raw,
            _cache: cache,
            _dataset: dataset,
        })
    }

    pub fn hash(&mut self, input: &[u8]) -> Digest {
        let mut output = [0; 32];
        // SAFETY: Each call has exclusive access to the VM, input stays live,
        // and the output pointer covers the exact upstream digest width.
        unsafe {
            randomx_calculate_hash(
                self.raw.as_ptr(),
                input.as_ptr().cast(),
                input.len(),
                output.as_mut_ptr().cast(),
            )
        };
        output
    }

    pub fn hash_header(&mut self, header_seed: Digest, nonce: u64) -> Digest {
        self.hash(&header_input(header_seed, nonce))
    }
}

impl Drop for Vm<'_> {
    fn drop(&mut self) {
        // SAFETY: The VM is uniquely owned and both backing owners still live.
        unsafe { randomx_destroy_vm(self.raw.as_ptr()) };
    }
}
