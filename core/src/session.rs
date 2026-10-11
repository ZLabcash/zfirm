//! The signer's side of the protocol, for any device.
//!
//! A [`Session`] turns what arrives (frames from the phone, the user's answer, the
//! result of slow work) into [`Step`]s: frames to send back, what to show, and work
//! to run. It never touches a screen, a radio or a thread itself, so the same logic
//! drives a Flipper (work on a worker thread, Bluetooth) and a Linux board (work
//! inline, USB serial).
//!
//! The flow: `HELLO` asks the user to share the viewing key, then answers `INFO`;
//! `SIGN` is reviewed ([`Work::Review`]), shown ([`Show::Review`]), and signed
//! ([`Work::Sign`]) only once the user approves it on the device.

use alloc::{sync::Arc, vec, vec::Vec};

use crate::{
    protocol::{self, Frame, Info, error, msg, status},
    request::{self, SignRequest, SpendSignature},
    sign::{self, Review},
};

/// What the device knows that the session needs to answer.
pub trait Host {
    /// The wallet's viewing key and facts, for `INFO`.
    fn info(&self) -> Option<Info>;
    /// The receiving address shown on the device, if any.
    fn address(&self) -> Option<(u32, alloc::string::String)>;
}

/// What the device should show.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Show {
    /// "Share this wallet's viewing key with the phone?" Answer with [`Session::answer`].
    PairPrompt,
    /// Slow work is running.
    Busy(&'static str),
    /// The checked transaction, to approve or refuse with [`Session::answer`].
    Review(Review),
    /// The outcome of a request.
    Done { ok: bool, note: &'static str },
    /// Back to whatever the device showed before the phone asked something.
    Resume,
}

/// Slow work to run, then report with [`Session::reviewed`] or [`Session::signed`].
#[derive(Debug, Clone)]
pub enum Work {
    Review(Arc<SignRequest>),
    Sign(Arc<SignRequest>),
}

#[derive(Debug, Default)]
pub struct Step {
    /// Encoded frames to send to the phone, in order.
    pub send: Vec<Vec<u8>>,
    pub show: Option<Show>,
    pub work: Option<Work>,
}

impl Step {
    fn reply(kind: u8, payload: &[u8]) -> Self {
        Step { send: vec![protocol::encode(kind, payload)], ..Step::default() }
    }

    fn error(code: u8, message: &str) -> Self {
        Self::reply(msg::ERROR, &protocol::encode_error(code, message))
    }

    fn and_send(mut self, kind: u8, payload: &[u8]) -> Self {
        self.send.push(protocol::encode(kind, payload));
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Waiting {
    Nothing,
    PairAnswer,
    /// Review or signing running.
    Work,
    /// A reviewed transaction on screen.
    SignAnswer,
}

#[derive(Debug)]
pub struct Session {
    paired: bool,
    waiting: Waiting,
    request: Option<Arc<SignRequest>>,
}

impl Default for Session {
    fn default() -> Self {
        Self::new()
    }
}

impl Session {
    pub fn new() -> Self {
        Session { paired: false, waiting: Waiting::Nothing, request: None }
    }

    pub fn paired(&self) -> bool {
        self.paired
    }

    /// Whether a request is in progress (the device should not start another).
    pub fn busy(&self) -> bool {
        self.waiting != Waiting::Nothing
    }

    /// A frame from the phone.
    pub fn frame(&mut self, f: Frame, host: &impl Host) -> Step {
        match f.kind {
            msg::PING => Step::reply(msg::PONG, &[]),
            msg::HELLO if self.paired => match host.info() {
                Some(info) => Step::reply(msg::INFO, &info.encode()),
                None => Step::error(error::LOCKED, "Locked"),
            },
            _ if self.busy() => Step::error(error::BUSY, "Busy"),
            msg::HELLO => {
                self.waiting = Waiting::PairAnswer;
                Step { show: Some(Show::PairPrompt), ..Step::reply(msg::STATUS, &[status::AWAITING_USER]) }
            }
            _ if !self.paired => Step::error(error::NOT_PAIRED, "Say hello first"),
            msg::GET_ADDRESS => match host.address() {
                Some((j, text)) => Step::reply(msg::ADDRESS, &protocol::encode_address(j, &text)),
                None => Step::error(error::LOCKED, "No address yet"),
            },
            msg::SIGN => {
                let Some(req) = SignRequest::decode(&f.payload) else {
                    return Step::error(error::BAD_REQUEST, "Bad request");
                };
                let req = Arc::new(req);
                self.request = Some(req.clone());
                self.waiting = Waiting::Work;
                Step {
                    show: Some(Show::Busy("Checking transaction")),
                    work: Some(Work::Review(req)),
                    ..Step::reply(msg::STATUS, &[status::WORKING])
                }
            }
            _ => Step::error(error::BAD_REQUEST, "Unknown message"),
        }
    }

    /// A frame that could not be decoded.
    pub fn bad_frame(&mut self) -> Step {
        Step::error(error::BAD_REQUEST, "Bad frame")
    }

    /// The user's answer to [`Show::PairPrompt`] or [`Show::Review`].
    pub fn answer(&mut self, yes: bool, host: &impl Host) -> Step {
        match (self.waiting, yes) {
            (Waiting::PairAnswer, true) => {
                self.waiting = Waiting::Nothing;
                let Some(info) = host.info() else {
                    return Step { show: Some(Show::Resume), ..Step::error(error::LOCKED, "Locked") };
                };
                self.paired = true;
                let mut step = Step { show: Some(Show::Resume), ..Step::reply(msg::INFO, &info.encode()) };
                if let Some((j, text)) = host.address() {
                    step = step.and_send(msg::ADDRESS, &protocol::encode_address(j, &text));
                }
                step
            }
            (Waiting::SignAnswer, true) => {
                let Some(req) = self.request.clone() else { return Step::default() };
                self.waiting = Waiting::Work;
                Step {
                    show: Some(Show::Busy("Signing")),
                    work: Some(Work::Sign(req)),
                    ..Step::reply(msg::STATUS, &[status::WORKING])
                }
            }
            (Waiting::PairAnswer, false) => {
                self.waiting = Waiting::Nothing;
                Step { show: Some(Show::Resume), ..Step::error(error::REJECTED, "Refused on the device") }
            }
            (Waiting::SignAnswer, false) => {
                self.reset();
                Step {
                    show: Some(Show::Done { ok: false, note: "Refused" }),
                    ..Step::error(error::REJECTED, "Refused on the device")
                }
            }
            _ => Step::default(),
        }
    }

    /// The result of [`Work::Review`].
    pub fn reviewed(&mut self, result: Result<Review, sign::Error>) -> Step {
        match result {
            Ok(review) => {
                self.waiting = Waiting::SignAnswer;
                Step { show: Some(Show::Review(review)), ..Step::reply(msg::STATUS, &[status::AWAITING_USER]) }
            }
            Err(e) => self.failed(e),
        }
    }

    /// The result of [`Work::Sign`].
    pub fn signed(&mut self, result: Result<Vec<SpendSignature>, sign::Error>) -> Step {
        match result {
            Ok(sigs) => {
                self.reset();
                Step {
                    show: Some(Show::Done { ok: true, note: "Signed: phone sends it" }),
                    ..Step::reply(msg::SIGNED, &request::encode_signatures(&sigs))
                }
            }
            Err(e) => self.failed(e),
        }
    }

    /// The link dropped: a new connection must be approved again.
    pub fn disconnected(&mut self) -> Step {
        let interrupted = self.waiting == Waiting::PairAnswer || self.waiting == Waiting::SignAnswer;
        self.paired = false;
        self.reset();
        Step { show: interrupted.then_some(Show::Resume), ..Step::default() }
    }

    /// The new receiving address shown on the device, for a paired phone to follow.
    pub fn address_changed(&self, index: u32, text: &str) -> Step {
        if self.paired {
            Step::reply(msg::ADDRESS, &protocol::encode_address(index, text))
        } else {
            Step::default()
        }
    }

    fn failed(&mut self, e: sign::Error) -> Step {
        self.reset();
        Step { show: Some(Show::Done { ok: false, note: e.message() }), ..Step::error(error::INVALID_TX, e.message()) }
    }

    fn reset(&mut self) {
        self.waiting = Waiting::Nothing;
        self.request = None;
    }
}

/// Runs a step's work inline, until no work is left (devices with time to spare).
pub fn run_inline<W: sign::Wallet, R: rand_core::RngCore + rand_core::CryptoRng>(
    session: &mut Session,
    mut step: Step,
    wallet: &W,
    rng: &mut R,
    mut out: impl FnMut(&Step),
) {
    loop {
        out(&step);
        step = match step.work.take() {
            Some(Work::Review(req)) => session.reviewed(sign::review(&req, wallet)),
            Some(Work::Sign(req)) => session.signed(sign::sign_reviewed(&req, wallet, &mut *rng)),
            None => return,
        };
    }
}
