extern crate nitrokey;
extern crate nitrokey_sys;
#[macro_use]
extern crate nitrokey_test;

mod util;

use std::ffi::CStr;
use std::process::Command;
use std::{thread, time};
use util::{ADMIN_PASSWORD, USER_PASSWORD};
use nitrokey::{Authenticate, CommandError, Config, Device, Storage};

static ADMIN_NEW_PASSWORD: &str = "1234567890";
static USER_NEW_PASSWORD: &str = "abcdefghij";

fn count_nitrokey_block_devices() -> usize {
    thread::sleep(time::Duration::from_secs(2));
    let output = Command::new("lsblk")
        .args(&["-o", "MODEL"])
        .output()
        .expect("Could not list block devices");
    String::from_utf8_lossy(&output.stdout)
        .split("\n")
        .filter(|&s| s == "Nitrokey Storage")
        .count()
}

fn assert_empty_serial_number() {
    unsafe {
        let ptr = nitrokey_sys::NK_device_serial_number();
        assert!(!ptr.is_null());
        let cstr = CStr::from_ptr(ptr);
        assert_eq!(cstr.to_string_lossy(), "");
    }
}

#[test_device]
fn get_serial_number(device: DeviceWrapper) {
    let result = device.get_serial_number();
    assert!(result.is_ok());
    let serial_number = result.unwrap();
    assert!(serial_number.is_ascii());
    assert!(serial_number.chars().all(|c| c.is_ascii_hexdigit()));
}
#[test_device]
fn get_firmware_version(device: Pro) {
    assert_eq!(0, device.get_major_firmware_version());
    let minor = device.get_minor_firmware_version();
    assert!(minor > 0);
}

fn admin_retry<T: Authenticate + Device>(device: T, suffix: &str, count: u8) -> T {
    let result = device.authenticate_admin(&(ADMIN_PASSWORD.to_owned() + suffix));
    let device = match result {
        Ok(admin) => admin.device(),
        Err((device, _)) => device,
    };
    assert_eq!(count, device.get_admin_retry_count());
    return device;
}

fn user_retry<T: Authenticate + Device>(device: T, suffix: &str, count: u8) -> T {
    let result = device.authenticate_user(&(USER_PASSWORD.to_owned() + suffix));
    let device = match result {
        Ok(admin) => admin.device(),
        Err((device, _)) => device,
    };
    assert_eq!(count, device.get_user_retry_count());
    return device;
}

#[test_device]
fn get_retry_count(device: DeviceWrapper) {
    let device = admin_retry(device, "", 3);
    let device = admin_retry(device, "123", 2);
    let device = admin_retry(device, "456", 1);
    let device = admin_retry(device, "", 3);

    let device = user_retry(device, "", 3);
    let device = user_retry(device, "123", 2);
    let device = user_retry(device, "456", 1);
    user_retry(device, "", 3);
}

#[test_device]
fn config(device: DeviceWrapper) {
    let admin = device.authenticate_admin(ADMIN_PASSWORD).unwrap();
    let config = Config::new(None, None, None, true);
    assert!(admin.write_config(config).is_ok());
    let get_config = admin.get_config().unwrap();
    assert_eq!(config, get_config);

    let config = Config::new(None, Some(9), None, true);
    assert_eq!(Err(CommandError::InvalidSlot), admin.write_config(config));

    let config = Config::new(Some(1), None, Some(0), false);
    assert!(admin.write_config(config).is_ok());
    let get_config = admin.get_config().unwrap();
    assert_eq!(config, get_config);

    let config = Config::new(None, None, None, false);
    assert!(admin.write_config(config).is_ok());
    let get_config = admin.get_config().unwrap();
    assert_eq!(config, get_config);
}

#[test_device]
fn change_user_pin(device: DeviceWrapper) {
    let device = device.authenticate_user(USER_PASSWORD).unwrap().device();
    let device = device.authenticate_user(USER_NEW_PASSWORD).unwrap_err().0;

    assert!(
        device
            .change_user_pin(USER_PASSWORD, USER_NEW_PASSWORD)
            .is_ok()
    );

    let device = device.authenticate_user(USER_PASSWORD).unwrap_err().0;
    let device = device
        .authenticate_user(USER_NEW_PASSWORD)
        .unwrap()
        .device();

    let result = device.change_user_pin(USER_PASSWORD, USER_PASSWORD);
    assert_eq!(Err(CommandError::WrongPassword), result);

    assert!(
        device
            .change_user_pin(USER_NEW_PASSWORD, USER_PASSWORD)
            .is_ok()
    );

    let device = device.authenticate_user(USER_PASSWORD).unwrap().device();
    assert!(device.authenticate_user(USER_NEW_PASSWORD).is_err());
}

#[test_device]
fn change_admin_pin(device: DeviceWrapper) {
    let device = device.authenticate_admin(ADMIN_PASSWORD).unwrap().device();
    let device = device.authenticate_admin(ADMIN_NEW_PASSWORD).unwrap_err().0;

    assert!(
        device
            .change_admin_pin(ADMIN_PASSWORD, ADMIN_NEW_PASSWORD)
            .is_ok()
    );

    let device = device.authenticate_admin(ADMIN_PASSWORD).unwrap_err().0;
    let device = device
        .authenticate_admin(ADMIN_NEW_PASSWORD)
        .unwrap()
        .device();

    assert_eq!(
        Err(CommandError::WrongPassword),
        device.change_admin_pin(ADMIN_PASSWORD, ADMIN_PASSWORD)
    );

    assert!(
        device
            .change_admin_pin(ADMIN_NEW_PASSWORD, ADMIN_PASSWORD)
            .is_ok()
    );

    let device = device.authenticate_admin(ADMIN_PASSWORD).unwrap().device();
    device.authenticate_admin(ADMIN_NEW_PASSWORD).unwrap_err();
}

fn require_failed_user_login<D>(device: D, password: &str, error: CommandError) -> D
where
  D: Device + Authenticate,
  nitrokey::User<D> : std::fmt::Debug,
{
    let result = device.authenticate_user(password);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(error, err.1);
    err.0
}

#[test_device]
fn unlock_user_pin(device: DeviceWrapper) {
    let device = device.authenticate_user(USER_PASSWORD).unwrap().device();
    assert!(
        device
            .unlock_user_pin(ADMIN_PASSWORD, USER_PASSWORD)
            .is_ok()
    );
    assert_eq!(
        Err(CommandError::WrongPassword),
        device.unlock_user_pin(USER_PASSWORD, USER_PASSWORD)
    );

    let wrong_password = USER_PASSWORD.to_owned() + "foo";
    let device = require_failed_user_login(device, &wrong_password, CommandError::WrongPassword);
    let device = require_failed_user_login(device, &wrong_password, CommandError::WrongPassword);
    let device = require_failed_user_login(device, &wrong_password, CommandError::WrongPassword);
    let device = require_failed_user_login(device, USER_PASSWORD, CommandError::WrongPassword);

    assert_eq!(
        Err(CommandError::WrongPassword),
        device.unlock_user_pin(USER_PASSWORD, USER_PASSWORD)
    );
    assert!(
        device
            .unlock_user_pin(ADMIN_PASSWORD, USER_PASSWORD)
            .is_ok()
    );
    device.authenticate_user(USER_PASSWORD).unwrap();
}

#[test_device]
fn encrypted_volume(device: Storage) {
    assert!(device.lock().is_ok());

    assert_eq!(1, count_nitrokey_block_devices());
    assert!(device.disable_encrypted_volume().is_ok());
    assert_eq!(1, count_nitrokey_block_devices());
    assert_eq!(
        Err(CommandError::WrongPassword),
        device.enable_encrypted_volume("123")
    );
    assert_eq!(1, count_nitrokey_block_devices());
    assert!(device.enable_encrypted_volume(USER_PASSWORD).is_ok());
    assert_eq!(2, count_nitrokey_block_devices());
    assert!(device.disable_encrypted_volume().is_ok());
    assert_eq!(1, count_nitrokey_block_devices());
}

#[test_device]
fn lock(device: Storage) {
    assert!(device.enable_encrypted_volume(USER_PASSWORD).is_ok());
    assert!(device.lock().is_ok());
    assert_eq!(1, count_nitrokey_block_devices());
}

#[test_device]
fn get_storage_status(device: Storage) {
    let status = device.get_status().unwrap();

    assert!(status.serial_number_sd_card > 0);
    assert!(status.serial_number_smart_card > 0);
}
