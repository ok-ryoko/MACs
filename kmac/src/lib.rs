//! Implementation of Keccak Message Authentication Code (KMAC)

#![no_std]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/26acc39f/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/26acc39f/logo.svg",
    html_root_url = "https://docs.rs/kmac/0.1.0"
)]
#![forbid(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs, rust_2018_idioms)]

use core::{fmt, slice};

pub use digest;

use digest::{
    block_buffer::Eager,
    core_api::{
        AlgorithmName,
        Block,
        BlockSizeUser,
        Buffer,
        BufferKindUser,
        CoreProxy,
        CoreWrapper,
        ExtendableOutputCore,
        UpdateCore,
    },
    typenum::Unsigned,
    HashMarker,
    KeyCustomInit,
    MacMarker,
};

#[cfg(feature = "reset")]
use digest::Reset;

use sha3::{CShake128, CShake256};

#[macro_use]
mod macros;

const FUNCTION_NAME: &[u8] = b"KMAC";

/// Generic core KMAC instance
#[derive(Clone)]
pub struct KmacCore<D>
where
    D: CoreProxy,
    D::Core: HashMarker
        + UpdateCore
        + ExtendableOutputCore
        + BufferKindUser<BufferKind = Eager>
        + Clone,
{
    digest: D::Core,
    #[cfg(feature = "reset")]
    initial_digest: D::Core,
}

impl<D> MacMarker for KmacCore<D>
where
    D: CoreProxy,
    D::Core: HashMarker
        + UpdateCore
        + ExtendableOutputCore
        + BufferKindUser<BufferKind = Eager>
        + Clone,
{
}

impl<D> BufferKindUser for KmacCore<D>
where
    D: CoreProxy,
    D::Core: HashMarker
        + UpdateCore
        + ExtendableOutputCore
        + BufferKindUser<BufferKind = Eager>
        + Clone,
{
    type BufferKind = Eager;
}

impl<D> BlockSizeUser for KmacCore<D>
where
    D: CoreProxy,
    D::Core: HashMarker
        + UpdateCore
        + ExtendableOutputCore
        + BufferKindUser<BufferKind = Eager>
        + Clone,
{
    type BlockSize = <<D as CoreProxy>::Core as BlockSizeUser>::BlockSize;
}

impl<D> UpdateCore for KmacCore<D>
where
    D: CoreProxy,
    D::Core: HashMarker
        + UpdateCore
        + ExtendableOutputCore
        + BufferKindUser<BufferKind = Eager>
        + Clone,
{
    #[inline(always)]
    fn update_blocks(&mut self, blocks: &[Block<Self>]) {
        self.digest.update_blocks(blocks);
    }
}

impl<D> ExtendableOutputCore for KmacCore<D>
where
    D: CoreProxy,
    D::Core: HashMarker
        + UpdateCore
        + ExtendableOutputCore
        + BufferKindUser<BufferKind = Eager>
        + Clone,
{
    type ReaderCore = <<D as CoreProxy>::Core as ExtendableOutputCore>::ReaderCore;

    #[inline]
    fn finalize_xof_core(&mut self, buffer: &mut Buffer<Self>) -> Self::ReaderCore {
        let mut b = [0u8; 9];
        buffer.digest_blocks(
            right_encode(0, &mut b),
            |blocks| { self.digest.update_blocks(blocks) },
        );
        self.digest.finalize_xof_core(buffer)
    }
}

#[cfg(feature = "reset")]
#[cfg_attr(docsrs, doc(cfg(feature = "reset")))]
impl<D> Reset for KmacCore<D>
where
    D: CoreProxy,
    D::Core: HashMarker
        + UpdateCore
        + ExtendableOutputCore
        + BufferKindUser<BufferKind = Eager>
    + Clone,
{
    #[inline(always)]
    fn reset(&mut self) {
        self.digest = self.initial_digest.clone();
    }
}

impl_kmac!(Kmac128, CShake128, "Kmac128");
impl_kmac!(Kmac256, CShake256, "Kmac128");

#[inline(always)]
pub(crate) fn right_encode(val: u64, buf: &mut [u8; 9]) -> &[u8] {
    buf[..8].copy_from_slice(&val.to_be_bytes());
    let off = buf[..7].iter().take_while(|&&a| a == 0).count();
    buf[8] = (8 - off) as u8;
    &buf[off..]
}

#[inline(always)]
pub(crate) fn left_encode(val: u64, buf: &mut [u8; 9]) -> &[u8] {
    buf[1..].copy_from_slice(&val.to_be_bytes());
    let off = buf[1..8].iter().take_while(|&&a| a == 0).count();
    buf[off] = (8 - off) as u8;
    &buf[off..]
}
