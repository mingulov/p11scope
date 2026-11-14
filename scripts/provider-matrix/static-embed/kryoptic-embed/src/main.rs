// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
//! A program with the kryoptic PKCS#11 provider statically linked.
//!
//! The binary exports `C_GetFunctionList` / `C_GetInterface` /
//! `C_GetInterfaceList` (the same entry points as the kryoptic .so,
//! forwarding to the statically linked tables) and self-drives the
//! embedded token *through that table*: initialize (creating the token
//! on first run), paced slot/session iterations, finalize. Every table
//! call is counted and the total printed as `CALLS=n`, the observation
//! oracle for the provider-matrix static-embed cell.
//!
//! Configuration: `KRYOPTIC_CONF` points at the token config (required),
//! `STATIC_EMBED_PIN` / `STATIC_EMBED_SO_PIN` carry the throwaway PINs
//! (required, never printed).
//!
//! Usage: kryoptic-static-embed [--iterations N] [--interval SECONDS]
//! Exit 0 on success (`CALLS=n` on stdout), 1 on a PKCS#11 failure,
//! 2 on usage or environment errors.

use kryoptic_lib::fns::general::{fn_get_function_list, fn_get_interface, fn_get_interface_list};
use kryoptic_lib::pkcs11::*;
use std::env;
use std::ptr;
use std::time::Duration;

/// Public export symbol, like the shared object: the statically linked
/// legacy function list. `inline(never)` keeps a standalone callable
/// copy (a binary inlines and drops single-use `no_mangle` wrappers).
#[inline(never)]
#[unsafe(no_mangle)]
pub extern "C" fn C_GetFunctionList(fnlist: CK_FUNCTION_LIST_PTR_PTR) -> CK_RV {
    fn_get_function_list(fnlist)
}

/// Public export symbol: the statically linked 3.x interface getter.
#[inline(never)]
#[unsafe(no_mangle)]
pub extern "C" fn C_GetInterface(
    interface_name: CK_UTF8CHAR_PTR,
    version: CK_VERSION_PTR,
    interface: CK_INTERFACE_PTR_PTR,
    flags: CK_FLAGS,
) -> CK_RV {
    fn_get_interface(interface_name, version, interface, flags)
}

/// Public export symbol: the statically linked interface list.
#[inline(never)]
#[unsafe(no_mangle)]
pub extern "C" fn C_GetInterfaceList(
    interfaces_list: CK_INTERFACE_PTR,
    count: CK_ULONG_PTR,
) -> CK_RV {
    fn_get_interface_list(interfaces_list, count)
}

/// Retain the entry exports in the image: a `#[used]` static of their
/// addresses (a binary otherwise drops `no_mangle` code nothing
/// references, and the file-scan fixture needs the exports present).
#[used]
static EXPORTS: (
    extern "C" fn(CK_FUNCTION_LIST_PTR_PTR) -> CK_RV,
    extern "C" fn(CK_UTF8CHAR_PTR, CK_VERSION_PTR, CK_INTERFACE_PTR_PTR, CK_FLAGS) -> CK_RV,
    extern "C" fn(CK_INTERFACE_PTR, CK_ULONG_PTR) -> CK_RV,
) = (
    C_GetFunctionList as _,
    C_GetInterface as _,
    C_GetInterfaceList as _,
);

fn usage() -> ! {
    eprintln!("usage: kryoptic-static-embed [--iterations N] [--interval SECONDS]");
    std::process::exit(2);
}

fn env_bytes(name: &str) -> Vec<u8> {
    match env::var(name) {
        Ok(value) if !value.is_empty() => value.into_bytes(),
        _ => {
            eprintln!("kryoptic-static-embed: {name} env must be set");
            std::process::exit(2);
        }
    }
}

fn parse_cli(args: &[String]) -> (u64, f64) {
    let mut iterations = 5.0;
    let mut interval = 1.0;
    let mut index = 0;
    while index < args.len() {
        let name = args[index].as_str();
        if name != "--iterations" && name != "--interval" {
            usage();
        }
        index += 1;
        if index >= args.len() {
            usage();
        }
        let value: f64 = args[index].parse::<f64>().unwrap_or_else(|_| usage());
        if name == "--iterations" {
            iterations = value;
        } else {
            interval = value;
        }
        index += 1;
    }
    (iterations.max(0.0) as u64, interval.max(0.0))
}

fn main() {
    let cli: Vec<String> = env::args().skip(1).collect();
    let (iterations, interval) = parse_cli(&cli);
    if env::var_os("KRYOPTIC_CONF").is_none() {
        eprintln!("kryoptic-static-embed: KRYOPTIC_CONF env must be set");
        std::process::exit(2);
    }
    let pin = env_bytes("STATIC_EMBED_PIN");
    let so_pin = env_bytes("STATIC_EMBED_SO_PIN");

    // Every table call below goes through the embedded table pointer,
    // so a file-scan observer would see genuine table calls. CALLS
    // counts table calls only (the export calls that fetch the tables
    // are not table calls).
    let mut calls: u64 = 0;
    macro_rules! table {
        ($list:expr, $name:ident ( $($arg:expr),* $(,)? )) => {{
            calls += 1;
            let slot = $list.$name.ok_or_else(|| {
                format!("embedded table misses {}", stringify!($name))
            })?;
            // SAFETY: arguments are valid PKCS#11 inputs; the table is
            // kryoptic's own static function list.
            unsafe { slot($($arg),*) }
        }};
    }
    let mut run = || -> Result<(), String> {
        // Acquire the table through our own export, exactly like an
        // external caller: this also keeps the export linked. Export
        // calls are not table calls, so CALLS does not count them.
        let mut list_ptr: *mut CK_FUNCTION_LIST = ptr::null_mut();
        let rv = C_GetFunctionList(&mut list_ptr);
        if rv != CKR_OK || list_ptr.is_null() {
            return Err(format!("C_GetFunctionList rv={rv:#x}"));
        }
        let mut iface_count: CK_ULONG = 0;
        let rv = C_GetInterfaceList(ptr::null_mut(), &mut iface_count);
        if rv != CKR_OK {
            return Err(format!("C_GetInterfaceList rv={rv:#x}"));
        }
        if EXPORTS.0 as usize == 0 {
            return Err("linked exports missing".to_string());
        }
        // SAFETY: kryoptic's static table outlives the process.
        let list = unsafe { &*list_ptr };
        let check = |step: &str, rv: CK_RV| -> Result<(), String> {
            if rv == CKR_OK {
                Ok(())
            } else {
                Err(format!("{step} rv={rv:#x}"))
            }
        };
        check("C_Initialize", table!(list, C_Initialize(ptr::null_mut())))?;
        let finalized = |calls: u64| println!("CALLS={calls}");
        let mut count: CK_ULONG = 0;
        check(
            "C_GetSlotList",
            table!(list, C_GetSlotList(0, ptr::null_mut(), &mut count)),
        )?;
        if count == 0 {
            let _ = table!(list, C_Finalize(ptr::null_mut()));
            finalized(calls);
            return Err("no slots in the embedded token".to_string());
        }
        let mut slots = vec![0 as CK_SLOT_ID; count as usize];
        check(
            "C_GetSlotList",
            table!(list, C_GetSlotList(0, slots.as_mut_ptr(), &mut count)),
        )?;
        let slot = slots[0];
        let mut token_info: CK_TOKEN_INFO = unsafe { std::mem::zeroed() };
        check(
            "C_GetTokenInfo",
            table!(list, C_GetTokenInfo(slot, &mut token_info)),
        )?;
        if token_info.flags & CKF_TOKEN_INITIALIZED == 0 {
            let mut label = [b' '; 32];
            let name = b"p11matrix";
            label[..name.len()].copy_from_slice(name);
            let mut so_pin = so_pin.clone();
            check(
                "C_InitToken",
                table!(
                    list,
                    C_InitToken(
                        slot,
                        so_pin.as_mut_ptr(),
                        so_pin.len() as CK_ULONG,
                        label.as_mut_ptr(),
                    )
                ),
            )?;
            let mut session: CK_SESSION_HANDLE = 0;
            check(
                "C_OpenSession",
                table!(
                    list,
                    C_OpenSession(
                        slot,
                        CKF_SERIAL_SESSION | CKF_RW_SESSION,
                        ptr::null_mut(),
                        None,
                        &mut session,
                    )
                ),
            )?;
            check(
                "C_Login",
                table!(
                    list,
                    C_Login(
                        session,
                        CKU_SO,
                        so_pin.as_mut_ptr(),
                        so_pin.len() as CK_ULONG,
                    )
                ),
            )?;
            let mut pin = pin.clone();
            check(
                "C_InitPIN",
                table!(
                    list,
                    C_InitPIN(session, pin.as_mut_ptr(), pin.len() as CK_ULONG,)
                ),
            )?;
            check("C_Logout", table!(list, C_Logout(session)))?;
            check("C_CloseSession", table!(list, C_CloseSession(session)))?;
        }
        let mut session: CK_SESSION_HANDLE = 0;
        check(
            "C_OpenSession",
            table!(
                list,
                C_OpenSession(
                    slot,
                    CKF_SERIAL_SESSION | CKF_RW_SESSION,
                    ptr::null_mut(),
                    None,
                    &mut session,
                )
            ),
        )?;
        let mut pin = pin.clone();
        check(
            "C_Login",
            table!(
                list,
                C_Login(session, CKU_USER, pin.as_mut_ptr(), pin.len() as CK_ULONG,)
            ),
        )?;
        for _ in 0..iterations {
            let mut slot_info: CK_SLOT_INFO = unsafe { std::mem::zeroed() };
            check(
                "C_GetSlotInfo",
                table!(list, C_GetSlotInfo(slot, &mut slot_info)),
            )?;
            let mut token_info: CK_TOKEN_INFO = unsafe { std::mem::zeroed() };
            check(
                "C_GetTokenInfo",
                table!(list, C_GetTokenInfo(slot, &mut token_info)),
            )?;
            let mut session_info: CK_SESSION_INFO = unsafe { std::mem::zeroed() };
            check(
                "C_GetSessionInfo",
                table!(list, C_GetSessionInfo(session, &mut session_info)),
            )?;
            if interval > 0.0 {
                std::thread::sleep(Duration::from_secs_f64(interval));
            }
        }
        check("C_Logout", table!(list, C_Logout(session)))?;
        check("C_CloseSession", table!(list, C_CloseSession(session)))?;
        check("C_Finalize", table!(list, C_Finalize(ptr::null_mut())))?;
        finalized(calls);
        Ok(())
    };
    if let Err(detail) = run() {
        eprintln!("kryoptic-static-embed: {detail}");
        std::process::exit(1);
    }
}
