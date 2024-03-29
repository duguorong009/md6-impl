#![no_std]

pub use digest::{self, Digest};

use core::fmt;
use digest::{
    block_buffer::Eager,
    consts::{U128, U16, U28, U32, U48, U64, U8},
    core_api::{
        AlgorithmName, Block, BlockSizeUser, Buffer, BufferKindUser, CoreWrapper, FixedOutputCore,
        OutputSizeUser, Reset, UpdateCore,
    },
    HashMarker, Output,
};

#[cfg(feature = "zeroize")]
use digest::zeroize::{Zeroize, ZeroizeOnDrop};

#[macro_use]
mod macros;
mod state;

use crate::state::MD6State;

impl_md6!(Md6_64Core, Md6_64, U128, U8, 64);
impl_md6!(Md6_128Core, Md6_128, U128, U16, 128);
impl_md6!(Md6_224Core, Md6_224, U128, U28, 224);
impl_md6!(Md6_256Core, Md6_256, U128, U32, 256);
impl_md6!(Md6_384Core, Md6_384, U128, U48, 384);
impl_md6!(Md6_512Core, Md6_512, U128, U64, 512);
