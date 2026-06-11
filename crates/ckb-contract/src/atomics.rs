//! Single-threaded polyfills for the legacy `__sync_*` atomic builtins.
//!
//! CKB-VM has no A (atomic) extension and runs scripts single-threaded, so `spin`/
//! `lazy_static` (pulled in by `bn`) only need single-hart semantics — i.e. plain
//! read-modify-write. With `-C target-feature=-a,+forced-atomics`, LLVM lowers
//! atomic load/store inline and resolves the C11 `__atomic_*` family via
//! compiler-builtins, but the legacy `__sync_*` RMW/CAS libcalls are unprovided; we
//! supply them here. (Sound because there is exactly one hart.)
#![allow(non_snake_case)]
use core::ptr::{read_volatile, write_volatile};

macro_rules! sync_ops {
    ($ty:ty, $cas:ident, $bcas:ident, $tas:ident, $faa:ident, $fas:ident, $fao:ident, $faand:ident, $fax:ident) => {
        #[no_mangle]
        pub unsafe extern "C" fn $cas(p: *mut $ty, old: $ty, new: $ty) -> $ty {
            let cur = read_volatile(p);
            if cur == old { write_volatile(p, new); }
            cur
        }
        #[no_mangle]
        pub unsafe extern "C" fn $bcas(p: *mut $ty, old: $ty, new: $ty) -> bool {
            let cur = read_volatile(p);
            if cur == old { write_volatile(p, new); true } else { false }
        }
        #[no_mangle]
        pub unsafe extern "C" fn $tas(p: *mut $ty, new: $ty) -> $ty {
            let cur = read_volatile(p);
            write_volatile(p, new);
            cur
        }
        #[no_mangle]
        pub unsafe extern "C" fn $faa(p: *mut $ty, v: $ty) -> $ty {
            let cur = read_volatile(p);
            write_volatile(p, cur.wrapping_add(v));
            cur
        }
        #[no_mangle]
        pub unsafe extern "C" fn $fas(p: *mut $ty, v: $ty) -> $ty {
            let cur = read_volatile(p);
            write_volatile(p, cur.wrapping_sub(v));
            cur
        }
        #[no_mangle]
        pub unsafe extern "C" fn $fao(p: *mut $ty, v: $ty) -> $ty {
            let cur = read_volatile(p);
            write_volatile(p, cur | v);
            cur
        }
        #[no_mangle]
        pub unsafe extern "C" fn $faand(p: *mut $ty, v: $ty) -> $ty {
            let cur = read_volatile(p);
            write_volatile(p, cur & v);
            cur
        }
        #[no_mangle]
        pub unsafe extern "C" fn $fax(p: *mut $ty, v: $ty) -> $ty {
            let cur = read_volatile(p);
            write_volatile(p, cur ^ v);
            cur
        }
    };
}

sync_ops!(u8,  __sync_val_compare_and_swap_1, __sync_bool_compare_and_swap_1, __sync_lock_test_and_set_1, __sync_fetch_and_add_1, __sync_fetch_and_sub_1, __sync_fetch_and_or_1, __sync_fetch_and_and_1, __sync_fetch_and_xor_1);
sync_ops!(u16, __sync_val_compare_and_swap_2, __sync_bool_compare_and_swap_2, __sync_lock_test_and_set_2, __sync_fetch_and_add_2, __sync_fetch_and_sub_2, __sync_fetch_and_or_2, __sync_fetch_and_and_2, __sync_fetch_and_xor_2);
sync_ops!(u32, __sync_val_compare_and_swap_4, __sync_bool_compare_and_swap_4, __sync_lock_test_and_set_4, __sync_fetch_and_add_4, __sync_fetch_and_sub_4, __sync_fetch_and_or_4, __sync_fetch_and_and_4, __sync_fetch_and_xor_4);
sync_ops!(u64, __sync_val_compare_and_swap_8, __sync_bool_compare_and_swap_8, __sync_lock_test_and_set_8, __sync_fetch_and_add_8, __sync_fetch_and_sub_8, __sync_fetch_and_or_8, __sync_fetch_and_and_8, __sync_fetch_and_xor_8);

#[no_mangle]
pub extern "C" fn __sync_synchronize() {}
