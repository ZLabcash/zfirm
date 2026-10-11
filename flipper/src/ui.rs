// Shared by both apps; each uses a subset.
#![allow(dead_code)]

//! What both apps share: the GUI shell, keys, the PIN pad, the crypto worker and
//! the busy / message screens.

use alloc::{sync::Arc, vec::Vec};
use core::{
    ffi::c_void,
    sync::atomic::{AtomicU32, Ordering},
};

use flipperzero::furi::thread::{self, JoinHandle};
use flipperzero_sys as sys;

use crate::{
    gfx::{Font, Gfx},
    sync::Mutex,
};

/// Appends `step` to /ext/apps_data/zflip/trace.txt (survives a crash). Debug aid.
pub fn breadcrumb(step: &str) {
    use flipperzero::{io::Write, storage::OpenOptions};
    if let Ok(mut f) = OpenOptions::new().write(true).open_append(true).open(c"/ext/apps_data/zflip/trace.txt") {
        let _ = f.write(step.as_bytes());
        let _ = f.write(b"\n");
    }
}

/// Progress (0–100) reported by the crypto worker for the busy screen.
pub static PROGRESS: AtomicU32 = AtomicU32::new(0);

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Key {
    Up,
    Down,
    Left,
    Right,
    Ok,
    Back,
    LongOk,
    LongBack,
}

fn key(e: &sys::InputEvent) -> Option<Key> {
    let short = e.type_ == sys::InputTypeShort || e.type_ == sys::InputTypeRepeat;
    let long = e.type_ == sys::InputTypeLong;
    Some(match e.key {
        k if k == sys::InputKeyUp && short => Key::Up,
        k if k == sys::InputKeyDown && short => Key::Down,
        k if k == sys::InputKeyLeft && short => Key::Left,
        k if k == sys::InputKeyRight && short => Key::Right,
        k if k == sys::InputKeyOk && short => Key::Ok,
        k if k == sys::InputKeyOk && long => Key::LongOk,
        k if k == sys::InputKeyBack && short => Key::Back,
        k if k == sys::InputKeyBack && long => Key::LongBack,
        _ => return None,
    })
}

/// How the keyboard of [`Shell::ask_text`] closed: 0 still open, 1 entered, 2 backed out.
static TEXT_DONE: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);

unsafe extern "C" fn text_entered(_: *mut c_void) {
    TEXT_DONE.store(1, Ordering::Release);
}

unsafe extern "C" fn text_back(_: *mut c_void) {
    TEXT_DONE.store(2, Ordering::Release);
}

/// A full-screen view port drawing `S` through `draw`.
pub struct Shell<S: 'static> {
    pub state: &'static Mutex<S>,
    /// Raw queue: the safe wrapper's timeouts go through f64 maths, which drags
    /// ~3 KiB of soft-float code into the app.
    queue: *mut sys::FuriMessageQueue,
    vp: *mut sys::ViewPort,
    gui: *mut sys::Gui,
    notify: *mut sys::NotificationApp,
    /// The draw callback's context, freed with the shell.
    ctx: *mut DrawCtx<S>,
}

pub struct DrawCtx<S: 'static> {
    state: &'static Mutex<S>,
    draw: fn(&Gfx, &S),
}

unsafe extern "C" fn draw_cb<S: 'static>(canvas: *mut sys::Canvas, ctx: *mut c_void) {
    let ctx = unsafe { &*(ctx as *const DrawCtx<S>) };
    let g = Gfx(canvas);
    g.clear();
    g.black();
    (ctx.draw)(&g, &ctx.state.lock());
}

unsafe extern "C" fn input_cb(event: *mut sys::InputEvent, ctx: *mut c_void) {
    unsafe { sys::furi_message_queue_put(ctx as *mut sys::FuriMessageQueue, event as *const c_void, 0) };
}

impl<S> Shell<S> {
    /// The state and queue live for the whole app run, and go with the shell. Even a
    /// few bytes left behind matter: they would split the heap the next app (or this
    /// one, coming back from its setup module) needs in one piece.
    pub fn new(state: S, draw: fn(&Gfx, &S)) -> Self {
        let state: &'static Mutex<S> = alloc::boxed::Box::leak(alloc::boxed::Box::new(Mutex::new(state)));
        let queue = unsafe { sys::furi_message_queue_alloc(8, core::mem::size_of::<sys::InputEvent>() as u32) };
        let ctx: *mut DrawCtx<S> = alloc::boxed::Box::into_raw(alloc::boxed::Box::new(DrawCtx { state, draw }));
        unsafe {
            let vp = sys::view_port_alloc();
            sys::view_port_draw_callback_set(vp, Some(draw_cb::<S>), ctx as *mut c_void);
            sys::view_port_input_callback_set(vp, Some(input_cb), queue as *mut c_void);
            let gui = sys::furi_record_open(c"gui".as_ptr()) as *mut sys::Gui;
            sys::gui_add_view_port(gui, vp, sys::GuiLayerFullscreen);
            let notify = sys::furi_record_open(c"notification".as_ptr()) as *mut sys::NotificationApp;
            Shell { state, queue, vp, gui, notify, ctx }
        }
    }

    /// Waits up to 40 ms (ticks are milliseconds) for a key, then redraws.
    pub fn next_key(&self) -> Option<Key> {
        let mut event = core::mem::MaybeUninit::<sys::InputEvent>::uninit();
        let got = unsafe { sys::furi_message_queue_get(self.queue, event.as_mut_ptr() as *mut c_void, 40) };
        unsafe { sys::view_port_update(self.vp) };
        if got != sys::FuriStatusOk {
            return None;
        }
        let event = unsafe { event.assume_init() };
        key(&event)
    }

    /// Replaces the state with `empty`, dropping everything the old one held (keys,
    /// addresses, words). Call before exiting: the state itself outlives the app, and
    /// what it still held would stay in RAM, secrets included, splitting the heap the
    /// next app needs whole.
    pub fn clear(&self, empty: S) {
        *self.state.lock() = empty;
    }

    /// Asks for a line of text with the Flipper's own keyboard, over this shell
    /// (which is hidden meanwhile): `None` if the user backs out.
    #[allow(dead_code)]
    pub fn ask_text(&self, header: &core::ffi::CStr, initial: &str, max: usize, min: usize) -> Option<alloc::string::String> {
        let mut buf = alloc::vec![0u8; max + 1];
        let n = initial.len().min(max);
        buf[..n].copy_from_slice(&initial.as_bytes()[..n]);
        TEXT_DONE.store(0, Ordering::Release);
        unsafe {
            sys::view_port_enabled_set(self.vp, false);
            let input = sys::text_input_alloc();
            let holder = sys::view_holder_alloc();
            sys::view_holder_set_view(holder, sys::text_input_get_view(input));
            sys::view_holder_attach_to_gui(holder, self.gui);
            sys::view_holder_set_back_callback(holder, Some(text_back), core::ptr::null_mut());
            sys::text_input_set_header_text(input, header.as_ptr());
            sys::text_input_set_minimum_length(input, min);
            sys::text_input_set_result_callback(
                input,
                Some(text_entered),
                core::ptr::null_mut(),
                buf.as_mut_ptr() as *mut core::ffi::c_char,
                buf.len(),
                false,
            );
            while TEXT_DONE.load(Ordering::Acquire) == 0 {
                sys::furi_delay_ms(50);
            }
            sys::view_holder_set_view(holder, core::ptr::null_mut());
            sys::view_holder_free(holder);
            sys::text_input_free(input);
            sys::view_port_enabled_set(self.vp, true);
        }
        if TEXT_DONE.load(Ordering::Acquire) != 1 {
            return None;
        }
        let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        core::str::from_utf8(&buf[..end]).ok().map(alloc::string::String::from)
    }

    pub fn buzz(&self, seq: &'static sys::NotificationSequence) {
        unsafe { sys::notification_message(self.notify, seq) };
    }

    pub fn success(&self) {
        self.buzz(unsafe { &sys::sequence_success });
    }

    pub fn error(&self) {
        self.buzz(unsafe { &sys::sequence_error });
    }

    pub fn attention(&self) {
        self.buzz(unsafe { &sys::sequence_double_vibro });
    }
}

impl<S> Drop for Shell<S> {
    fn drop(&mut self) {
        unsafe {
            sys::gui_remove_view_port(self.gui, self.vp);
            sys::view_port_free(self.vp);
            sys::furi_message_queue_free(self.queue);
            sys::furi_record_close(c"gui".as_ptr());
            sys::furi_record_close(c"notification".as_ptr());
            // Nothing draws any more: the context and the state can go.
            drop(alloc::boxed::Box::from_raw(self.ctx));
            drop(alloc::boxed::Box::from_raw(self.state as *const Mutex<S> as *mut Mutex<S>));
        }
    }
}

type Task<J> = alloc::boxed::Box<dyn FnOnce() -> J + Send>;

struct Shared<J> {
    task: Mutex<Option<Task<J>>>,
    out: Mutex<Option<J>>,
    stop: core::sync::atomic::AtomicBool,
    /// Released once per job (or to stop); the thread sleeps on it.
    wake: *mut sys::FuriSemaphore,
}

unsafe impl<J: Send> Send for Shared<J> {}
unsafe impl<J: Send> Sync for Shared<J> {}

/// One crypto job at a time, on a thread with a large stack that lives as long as
/// the app. Creating it once, first, matters: once the heap is fragmented there may
/// be no single free block left for a fresh 10 KiB stack.
pub struct Worker<J: Send + 'static> {
    handle: Option<JoinHandle>,
    shared: Arc<Shared<J>>,
    busy: bool,
}

impl<J: Send + 'static> Worker<J> {
    pub fn new(stack: usize) -> Self {
        let shared = Arc::new(Shared {
            task: Mutex::new(None),
            out: Mutex::new(None),
            stop: core::sync::atomic::AtomicBool::new(false),
            wake: unsafe { sys::furi_semaphore_alloc(1, 0) },
        });
        let inner = shared.clone();
        let handle = thread::Builder::new().stack_size(stack).spawn(move || {
            loop {
                unsafe { sys::furi_semaphore_acquire(inner.wake, u32::MAX) };
                if inner.stop.load(Ordering::Acquire) {
                    return 0;
                }
                let task = inner.task.lock().take();
                if let Some(task) = task {
                    let out = task();
                    *inner.out.lock() = Some(out);
                }
            }
        });
        Worker { handle: Some(handle), shared, busy: false }
    }

    pub fn busy(&self) -> bool {
        self.busy
    }

    pub fn spawn(&mut self, f: impl FnOnce() -> J + Send + 'static) {
        PROGRESS.store(0, Ordering::Relaxed);
        *self.shared.task.lock() = Some(alloc::boxed::Box::new(f));
        self.busy = true;
        self.wake();
    }

    fn wake(&self) {
        unsafe { sys::furi_semaphore_release(self.shared.wake) };
    }

    /// The finished job's result, if any.
    pub fn poll(&mut self) -> Option<J> {
        let out = self.shared.out.lock().take()?;
        self.busy = false;
        Some(out)
    }

    /// Stops the thread once its current job (if any) is done.
    pub fn wait(&mut self) {
        self.shared.stop.store(true, Ordering::Release);
        self.wake();
        if let Some(handle) = self.handle.take() {
            handle.join();
            unsafe { sys::furi_semaphore_free(self.shared.wake) };
        }
    }
}

pub const PIN_MIN: usize = 6;
pub const PIN_MAX: usize = 10;

pub struct PinPad {
    digits: [u8; PIN_MAX],
    len: usize,
    cur: u8,
}

pub enum Pin {
    Editing,
    Entered(Vec<u8>),
    Cancel,
}

impl PinPad {
    pub const fn new() -> Self {
        PinPad { digits: [0; PIN_MAX], len: 0, cur: 0 }
    }

    pub fn clear(&mut self) {
        self.digits = [0; PIN_MAX];
        self.len = 0;
        self.cur = 0;
    }

    /// ▲▼ pick a digit, ▶/OK append it, ◀/Back erase, hold OK to submit.
    pub fn key(&mut self, k: Key) -> Pin {
        match k {
            Key::Up => self.cur = (self.cur + 1) % 10,
            Key::Down => self.cur = (self.cur + 9) % 10,
            Key::Right | Key::Ok if self.len < PIN_MAX => {
                self.digits[self.len] = self.cur;
                self.len += 1;
                self.cur = 0;
            }
            Key::Left | Key::Back if self.len > 0 => {
                self.len -= 1;
                self.cur = self.digits[self.len];
            }
            Key::Back | Key::LongBack => return Pin::Cancel,
            Key::LongOk if self.len >= PIN_MIN => {
                let pin = self.digits[..self.len].iter().map(|d| b'0' + d).collect();
                self.clear();
                return Pin::Entered(pin);
            }
            _ => {}
        }
        Pin::Editing
    }

    pub fn draw(&self, g: &Gfx, title: &str, note: &str) {
        g.title(title);
        let n = self.len as i32 + 1;
        let x0 = 64 - n * 5;
        for i in 0..self.len as i32 {
            g.disc(x0 + i * 10 + 4, 30, 3);
        }
        if self.len < PIN_MAX {
            let cx = x0 + self.len as i32 * 10;
            g.font(Font::Big);
            g.text(cx + 1, 35, digit(self.cur));
            g.line(cx, 37, cx + 8, 37);
        }
        g.font(Font::Small);
        g.center(48, note);
        g.hints("^v digit", if self.len >= PIN_MIN { "Hold OK" } else { "" });
    }
}

fn digit(d: u8) -> &'static str {
    ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9"][d as usize % 10]
}

/// The shield forging while the worker runs.
pub fn draw_busy(g: &Gfx, label: &str, frame: u32) {
    let p = PROGRESS.load(Ordering::Relaxed);
    g.shield(64, 24, ((frame % 90) * 1000 / 90) as i32, frame);
    g.font(Font::Small);
    g.center(53, label);
    if p > 0 {
        g.progress(56, p);
    }
}

/// Centred lines separated by '\n'.
pub fn draw_message(g: &Gfx, text: &str) {
    g.font(Font::Small);
    for (i, line) in text.split('\n').enumerate() {
        g.center(24 + i as i32 * 11, line);
    }
    g.hints("", "OK");
}
