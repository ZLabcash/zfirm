// Shared by both apps; each uses a subset.
#![allow(dead_code)]

//! A data-owning mutex over `FuriMutex`, shared between the app thread, the GUI
//! draw callback and the crypto worker.

use core::{
    cell::UnsafeCell,
    ops::{Deref, DerefMut},
};

use flipperzero_sys as sys;

pub struct Mutex<T> {
    raw: *mut sys::FuriMutex,
    data: UnsafeCell<T>,
}

unsafe impl<T: Send> Send for Mutex<T> {}
unsafe impl<T: Send> Sync for Mutex<T> {}

impl<T> Mutex<T> {
    pub fn new(value: T) -> Self {
        Mutex {
            raw: unsafe { sys::furi_mutex_alloc(sys::FuriMutexTypeNormal) },
            data: UnsafeCell::new(value),
        }
    }

    pub fn lock(&self) -> Guard<'_, T> {
        unsafe { sys::furi_mutex_acquire(self.raw, u32::MAX) };
        Guard(self)
    }
}

impl<T> Drop for Mutex<T> {
    fn drop(&mut self) {
        unsafe { sys::furi_mutex_free(self.raw) };
    }
}

pub struct Guard<'a, T>(&'a Mutex<T>);

impl<T> Deref for Guard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        unsafe { &*self.0.data.get() }
    }
}

impl<T> DerefMut for Guard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        unsafe { &mut *self.0.data.get() }
    }
}

impl<T> Drop for Guard<'_, T> {
    fn drop(&mut self) {
        unsafe { sys::furi_mutex_release(self.0.raw) };
    }
}
