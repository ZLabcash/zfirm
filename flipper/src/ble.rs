// Shared by both apps; each uses a subset.
#![allow(dead_code)]

//! A ZFlip BLE profile: the firmware's serial GATT service under our own profile
//! template, name and bonding keys.
//!
//! Starting the stock `ble_profile_serial` would make the Bt service open an RPC
//! session for the official Flipper app on every connection and take over the data
//! callback; a profile of our own keeps the link for ZFlip. Pairing shows a 6-digit
//! code on the Flipper (`GapPairingPinCodeShow`) and bonds are kept in our own key
//! file, apart from the official app's.

use core::{
    ffi::c_void,
    ptr,
    sync::atomic::{AtomicBool, AtomicU8, Ordering},
};

use flipperzero::furi::stream_buffer::{self, StreamBuffer};
use flipperzero_sys as sys;

const KEYS_PATH: &core::ffi::CStr = c"/ext/apps_data/zflip/.bt.keys";
/// Bytes per notification: below the 182 a default iOS MTU (185) allows.
const PACKET: usize = 160;
const RX_BUFFER: u16 = 1024;

#[repr(C)]
struct Profile {
    base: sys::FuriHalBleProfileBase,
    dev_info: *mut sys::BleServiceDevInfo,
    battery: *mut sys::BleServiceBattery,
    serial: *mut sys::BleServiceSerial,
}

static TEMPLATE: sys::FuriHalBleProfileTemplate = sys::FuriHalBleProfileTemplate {
    start: Some(profile_start),
    stop: Some(profile_stop),
    get_gap_config: Some(profile_gap_config),
};

/// The serial service of the running profile (set by `profile_start`).
static mut SERIAL: *mut sys::BleServiceSerial = ptr::null_mut();
static SENT: AtomicBool = AtomicBool::new(true);
static STATUS: AtomicU8 = AtomicU8::new(0);
static mut RX: Option<stream_buffer::Sender> = None;

unsafe extern "C" fn profile_start(_params: sys::FuriHalBleProfileParams) -> *mut sys::FuriHalBleProfileBase {
    unsafe {
        let p = sys::malloc(core::mem::size_of::<Profile>() as u32) as *mut Profile;
        (*p).base.config = &TEMPLATE;
        (*p).dev_info = sys::ble_svc_dev_info_start();
        (*p).battery = sys::ble_svc_battery_start(true);
        (*p).serial = sys::ble_svc_serial_start();
        SERIAL = (*p).serial;
        sys::ble_svc_serial_set_callbacks((*p).serial, RX_BUFFER, Some(serial_event), ptr::null_mut());
        p as *mut sys::FuriHalBleProfileBase
    }
}

unsafe extern "C" fn profile_stop(base: *mut sys::FuriHalBleProfileBase) {
    unsafe {
        let p = base as *mut Profile;
        SERIAL = ptr::null_mut();
        sys::ble_svc_battery_stop((*p).battery);
        sys::ble_svc_dev_info_stop((*p).dev_info);
        sys::ble_svc_serial_stop((*p).serial);
        sys::free(p as *mut c_void);
    }
}

unsafe extern "C" fn profile_gap_config(config: *mut sys::GapConfig, _params: sys::FuriHalBleProfileParams) {
    unsafe {
        let c = &mut *config;
        *c = core::mem::zeroed();
        c.adv_service.UUID_Type = 0x01; // UUID_TYPE_16
        c.adv_service.Service_UUID_16 = 0x3080 | sys::furi_hal_version_get_hw_color().0 as u16;
        c.appearance_char = 0x8600;
        c.bonding_mode = true;
        c.pairing_method = sys::GapPairingPinCodeShow;
        c.conn_param = sys::GapConnectionParamsRequest {
            conn_int_min: 0x06,
            conn_int_max: 0x24,
            slave_latency: 0,
            supervisor_timeout: 0,
        };
        // A MAC of its own so phones don't mix our bond with the official profile's.
        ptr::copy_nonoverlapping(sys::furi_hal_version_get_ble_mac(), c.mac_address.as_mut_ptr(), 6);
        c.mac_address[2] = c.mac_address[2].wrapping_add(0x5A);
        // Advertised name: AD type 0x09 (complete local name), then "ZFlip <name>".
        let mut name = [0u8; 18];
        name[0] = 0x09;
        let mut n = 1;
        for &b in b"ZFlip " {
            name[n] = b;
            n += 1;
        }
        let mut own = sys::furi_hal_version_get_name_ptr() as *const u8;
        while !own.is_null() && *own != 0 && n < 17 {
            name[n] = *own;
            own = own.add(1);
            n += 1;
        }
        for (dst, src) in c.adv_name.iter_mut().zip(name.iter()) {
            *dst = *src as core::ffi::c_char;
        }
    }
}

unsafe extern "C" fn serial_event(event: sys::SerialServiceEvent, _ctx: *mut c_void) -> u16 {
    if event.event == sys::SerialServiceEventTypeDataReceived {
        let data = unsafe { core::slice::from_raw_parts(event.data.buffer, event.data.size as usize) };
        if let Some(tx) = unsafe { (*ptr::addr_of!(RX)).as_ref() } {
            tx.send(data);
        }
    } else if event.event == sys::SerialServiceEventTypeDataSent {
        SENT.store(true, Ordering::Release);
    }
    RX_BUFFER
}

unsafe extern "C" fn status_changed(status: sys::BtStatus, _ctx: *mut c_void) {
    STATUS.store(status.0, Ordering::Release);
}

pub struct Link {
    bt: *mut sys::Bt,
    rx: stream_buffer::Receiver,
}

impl Link {
    /// Switches the radio to the ZFlip profile and starts advertising.
    pub fn start() -> Option<Link> {
        let (tx, rx) = StreamBuffer::new(core::num::NonZeroUsize::new(2048).unwrap(), 1).into_stream();
        unsafe {
            RX = Some(tx);
            let bt = sys::furi_record_open(c"bt".as_ptr()) as *mut sys::Bt;
            sys::bt_disconnect(bt);
            sys::furi_delay_ms(200);
            sys::bt_keys_storage_set_storage_path(bt, KEYS_PATH.as_ptr());
            if sys::bt_profile_start(bt, &TEMPLATE, ptr::null_mut()).is_null() {
                sys::bt_keys_storage_set_default_path(bt);
                sys::furi_record_close(c"bt".as_ptr());
                return None;
            }
            sys::bt_set_status_changed_callback(bt, Some(status_changed), ptr::null_mut());
            sys::furi_hal_bt_start_advertising();
            Some(Link { bt, rx })
        }
    }

    pub fn connected(&self) -> bool {
        STATUS.load(Ordering::Acquire) == sys::BtStatusConnected.0
    }

    /// Bytes received since the last call.
    pub fn recv(&self, buf: &mut [u8]) -> usize {
        self.rx.recv(buf)
    }

    /// Sends bytes as notifications, waiting for each one to go out.
    pub fn send(&self, mut data: &[u8]) -> bool {
        while !data.is_empty() {
            let n = data.len().min(PACKET);
            let mut packet = [0u8; PACKET];
            packet[..n].copy_from_slice(&data[..n]);
            SENT.store(false, Ordering::Release);
            let serial = unsafe { *ptr::addr_of!(SERIAL) };
            if serial.is_null() || !unsafe { sys::ble_svc_serial_update_tx(serial, packet.as_mut_ptr(), n as u16) } {
                return false;
            }
            let start = unsafe { sys::furi_get_tick() };
            while !SENT.load(Ordering::Acquire) {
                if unsafe { sys::furi_get_tick() }.wrapping_sub(start) > 1000 {
                    return false;
                }
                unsafe { sys::furi_delay_ms(2) };
            }
            data = &data[n..];
        }
        true
    }
}

impl Drop for Link {
    fn drop(&mut self) {
        unsafe {
            sys::bt_set_status_changed_callback(self.bt, None, ptr::null_mut());
            sys::bt_disconnect(self.bt);
            sys::furi_delay_ms(200);
            sys::bt_keys_storage_set_default_path(self.bt);
            sys::bt_profile_restore_default(self.bt);
            sys::furi_record_close(c"bt".as_ptr());
            RX = None;
        }
    }
}
