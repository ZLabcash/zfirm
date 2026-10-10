//! The compact signing request the phone derives from a PCZT (see the `bridge`
//! crate), and the signatures the device returns.
//!
//! It carries every effecting field of the Orchard/Ironwood bundles (so the device
//! can compute the sighash itself) plus the openings of each action's commitments
//! (values, recipients, randomness) so the device can check what it displays. The
//! phone is untrusted: nothing in here is believed until [`crate::sign::review`]
//! has checked it against the commitments.

use alloc::{string::String, vec::Vec};

use orchard::bundle::BundleVersion;

pub const FORMAT: u8 = 1;
pub const ENC_CIPHERTEXT_SIZE: usize = 580;
pub const OUT_CIPHERTEXT_SIZE: usize = 80;

/// Wire ids for Orchard protocol bundle versions.
pub mod version {
    pub const ORCHARD_V1: u8 = 0;
    pub const ORCHARD_V2: u8 = 1;
    pub const ORCHARD_V3: u8 = 2;
    pub const IRONWOOD_V3: u8 = 3;
}

pub fn bundle_version(id: u8) -> Option<BundleVersion> {
    Some(match id {
        version::ORCHARD_V1 => BundleVersion::orchard_insecure_v1(),
        version::ORCHARD_V2 => BundleVersion::orchard_v2(),
        version::ORCHARD_V3 => BundleVersion::orchard_v3(),
        version::IRONWOOD_V3 => BundleVersion::ironwood_v3(),
        _ => return None,
    })
}

pub fn bundle_version_id(v: BundleVersion) -> Option<u8> {
    [
        version::ORCHARD_V1,
        version::ORCHARD_V2,
        version::ORCHARD_V3,
        version::IRONWOOD_V3,
    ]
    .into_iter()
    .find(|&id| bundle_version(id) == Some(v))
}

/// Who an output belongs to, as claimed by the phone. The device re-derives the
/// address to check the claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Owner {
    /// Not this wallet (a payment, or a dummy output with zero value).
    Other,
    /// This wallet's receiving address at diversifier index `j`.
    External(u32),
    /// This wallet's change address at diversifier index `j`.
    Internal(u32),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Action {
    pub cv_net: [u8; 32],
    pub nullifier: [u8; 32],
    pub rk: [u8; 32],
    pub cmx: [u8; 32],
    pub epk: [u8; 32],
    pub enc_ciphertext: Vec<u8>,
    pub out_ciphertext: [u8; OUT_CIPHERTEXT_SIZE],
    /// Value commitment trapdoor.
    pub rcv: [u8; 32],
    pub spend_value: u64,
    /// Spend authorization randomizer.
    pub alpha: [u8; 32],
    pub output_recipient: [u8; 43],
    pub output_value: u64,
    pub output_rseed: [u8; 32],
    pub owner: Owner,
    /// The recipient address as the user typed it, or empty.
    pub user_address: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bundle {
    pub version: u8,
    pub flags: u8,
    pub value_balance: i64,
    pub anchor: [u8; 32],
    pub actions: Vec<Action>,
}

impl Bundle {
    pub fn is_ironwood(&self) -> bool {
        self.version == version::IRONWOOD_V3
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignRequest {
    pub tx_version: u32,
    pub version_group_id: u32,
    pub branch_id: u32,
    pub lock_time: u32,
    pub expiry_height: u32,
    /// At most one Orchard-pool bundle and one Ironwood bundle.
    pub bundles: Vec<Bundle>,
}

/// One spend authorization signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpendSignature {
    pub ironwood: bool,
    pub action_index: u16,
    pub signature: [u8; 64],
}

impl SignRequest {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer(Vec::new());
        w.u8(FORMAT);
        w.u32(self.tx_version);
        w.u32(self.version_group_id);
        w.u32(self.branch_id);
        w.u32(self.lock_time);
        w.u32(self.expiry_height);
        w.u8(self.bundles.len() as u8);
        for b in &self.bundles {
            w.u8(b.version);
            w.u8(b.flags);
            w.bytes(&b.value_balance.to_le_bytes());
            w.bytes(&b.anchor);
            w.u16(b.actions.len() as u16);
            for a in &b.actions {
                w.bytes(&a.cv_net);
                w.bytes(&a.nullifier);
                w.bytes(&a.rk);
                w.bytes(&a.cmx);
                w.bytes(&a.epk);
                w.bytes(&a.enc_ciphertext);
                w.bytes(&a.out_ciphertext);
                w.bytes(&a.rcv);
                w.u64(a.spend_value);
                w.bytes(&a.alpha);
                w.bytes(&a.output_recipient);
                w.u64(a.output_value);
                w.bytes(&a.output_rseed);
                match a.owner {
                    Owner::Other => w.u8(0),
                    Owner::External(j) => {
                        w.u8(1);
                        w.u32(j)
                    }
                    Owner::Internal(j) => {
                        w.u8(2);
                        w.u32(j)
                    }
                }
                w.u16(a.user_address.len() as u16);
                w.bytes(a.user_address.as_bytes());
            }
        }
        w.0
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let mut r = Reader(bytes);
        if r.u8()? != FORMAT {
            return None;
        }
        let mut req = SignRequest {
            tx_version: r.u32()?,
            version_group_id: r.u32()?,
            branch_id: r.u32()?,
            lock_time: r.u32()?,
            expiry_height: r.u32()?,
            bundles: Vec::new(),
        };
        for _ in 0..r.u8()? {
            let mut b = Bundle {
                version: r.u8()?,
                flags: r.u8()?,
                value_balance: i64::from_le_bytes(r.array()?),
                anchor: r.array()?,
                actions: Vec::new(),
            };
            for _ in 0..r.u16()? {
                b.actions.push(Action {
                    cv_net: r.array()?,
                    nullifier: r.array()?,
                    rk: r.array()?,
                    cmx: r.array()?,
                    epk: r.array()?,
                    enc_ciphertext: r.take(ENC_CIPHERTEXT_SIZE)?.to_vec(),
                    out_ciphertext: r.array()?,
                    rcv: r.array()?,
                    spend_value: r.u64()?,
                    alpha: r.array()?,
                    output_recipient: r.array()?,
                    output_value: r.u64()?,
                    output_rseed: r.array()?,
                    owner: match r.u8()? {
                        0 => Owner::Other,
                        1 => Owner::External(r.u32()?),
                        2 => Owner::Internal(r.u32()?),
                        _ => return None,
                    },
                    user_address: {
                        let len = r.u16()? as usize;
                        String::from(core::str::from_utf8(r.take(len)?).ok()?)
                    },
                });
            }
            req.bundles.push(b);
        }
        r.0.is_empty().then_some(req)
    }
}

pub fn encode_signatures(sigs: &[SpendSignature]) -> Vec<u8> {
    let mut w = Writer(Vec::with_capacity(2 + sigs.len() * 67));
    w.u16(sigs.len() as u16);
    for s in sigs {
        w.u8(s.ironwood as u8);
        w.u16(s.action_index);
        w.bytes(&s.signature);
    }
    w.0
}

pub fn decode_signatures(bytes: &[u8]) -> Option<Vec<SpendSignature>> {
    let mut r = Reader(bytes);
    let mut out = Vec::new();
    for _ in 0..r.u16()? {
        out.push(SpendSignature {
            ironwood: match r.u8()? {
                0 => false,
                1 => true,
                _ => return None,
            },
            action_index: r.u16()?,
            signature: r.array()?,
        });
    }
    r.0.is_empty().then_some(out)
}

struct Writer(Vec<u8>);

impl Writer {
    fn u8(&mut self, v: u8) {
        self.0.push(v);
    }
    fn u16(&mut self, v: u16) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    fn u32(&mut self, v: u32) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    fn u64(&mut self, v: u64) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    fn bytes(&mut self, v: &[u8]) {
        self.0.extend_from_slice(v);
    }
}

struct Reader<'a>(&'a [u8]);

impl Reader<'_> {
    fn take(&mut self, n: usize) -> Option<&[u8]> {
        if self.0.len() < n {
            return None;
        }
        let (head, tail) = self.0.split_at(n);
        self.0 = tail;
        Some(head)
    }
    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }
    fn u16(&mut self) -> Option<u16> {
        self.array().map(u16::from_le_bytes)
    }
    fn u32(&mut self) -> Option<u32> {
        self.array().map(u32::from_le_bytes)
    }
    fn u64(&mut self) -> Option<u64> {
        self.array().map(u64::from_le_bytes)
    }
    fn array<const N: usize>(&mut self) -> Option<[u8; N]> {
        self.take(N).map(crate::arr)
    }
}
