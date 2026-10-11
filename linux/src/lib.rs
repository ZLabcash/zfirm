//! ZFirm on Linux, as a library: the device logic ([`app`]), the sealed wallet
//! ([`vault`]), the link to the phone ([`link`]) and the screens ([`term`], `lcd`).

pub mod app;
pub mod canvas;
#[cfg(feature = "lcd")]
pub mod lcd;
pub mod link;
pub mod term;
pub mod vault;

/// Uses Sinsemilla's full table of S(j) points (64 KiB, compiled in) instead of
/// computing each one: a Linux board has the memory a Flipper app lacks.
pub fn use_sinsemilla_table() {
    fn table(j: u32) -> Option<pasta_curves::pallas::Affine> {
        use pasta_curves::arithmetic::CurveAffine;
        let (x, y) = sinsemilla::SINSEMILLA_S.get(j as usize)?;
        Option::from(pasta_curves::pallas::Affine::from_xy(*x, *y))
    }
    sinsemilla::set_s_provider(Some(table));
}
