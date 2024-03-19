macro_rules! impl_md6 {
    (
        $name:ident, $full_name:ident, $output_size:ident, $rate:ident
    ) => {
        #[doc = "Core "]
        #[doc = " hasher state."]
        #[derive(Clone)]
        #[allow(non_camel_case_types)]
        pub struct $name {
            state: Md6State,
        }

        #[doc = " hasher state."]
        pub type $full_name = CoreWrapper<$name>;

        impl HashMarker for $name {}

        impl BlockSizeUser for $name {
            type BlockSize = $rate;
        }

        impl BufferKindUser for $name {
            type BufferKind = Eager;
        }

        impl OutputSizeUser for $name {
            type OutputSize = $output_size;
        }

        impl UpdateCore for $name {
            #[inline]
            fn update_blocks(&mut self, blocks: &[Block<Self>]) {
                for block in blocks {
                    self.state.update(block, block.len() * 8)
                }
            }
        }

        impl FixedOutputCore for $name {
            #[inline]
            fn finalize_fixed_core(&mut self, buffer: &mut Buffer<Self>, out: &mut Output<Self>) {
                self.state.finalize(out)
            }
        }

        impl Default for $name {
            #[inline]
            fn default() -> Self {
                Self {
                    state: Md6State::init($output_size)
                }
            }
        }

        impl Reset for $name {
            #[inline]
            fn reset(&mut self) {
                *self = Default::default();
            }
        }

        impl AlgorithmName for $name {
            fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(stringify!($full_name))
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($name), " { ... }"))
            }
        }

        impl Drop for $name {
            fn drop(&mut self) {
                #[cfg(feature = "zeroize")]
                {
                    self.state.state.zeroize();
                }
            }
        }
        
        #[cfg(feature = "zeroize")]
        impl ZeroizeOnDrop for $name {}
    };
}