macro_rules! impl_kmac {
    (
        $name:ident, $core:ident, $alg_name:expr $(,)?
    ) => {
        impl KeyCustomInit for KmacCore<$core> {
            fn new_with_customization(key: &[u8], customization: &[u8]) -> Self {
                let mut core = <$core as CoreProxy>::Core::new_with_function_name(FUNCTION_NAME, customization);
                let mut buffer = Buffer::<<$core as CoreProxy>::Core>::default();
                let mut b = [0u8; 9];

                buffer.digest_blocks(
                    left_encode(<$core as BlockSizeUser>::BlockSize::to_u64(), &mut b),
                    |blocks| { core.update_blocks(blocks) },
                );
                buffer.digest_blocks(
                    left_encode((key.len() * 8) as u64, &mut b),
                    |blocks| { core.update_blocks(blocks) },
                );
                buffer.digest_blocks(
                    key,
                    |blocks| { core.update_blocks(blocks) },
                );
                let block = buffer.pad_with_zeros();
                core.update_blocks(slice::from_ref(&block));

                #[cfg(not(feature = "reset"))]
                let result = Self { digest: core };
                #[cfg(feature = "reset")]
                let result = Self { digest: core.clone(), initial_digest: core };

                #[allow(clippy::needless_return)]
                return result
            }
        }

        impl AlgorithmName for KmacCore<$core> {
            fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(stringify!($alg_name))
            }
        }

        impl fmt::Debug for KmacCore<$core> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(stringify!($alg_name))
            }
        }

        #[doc = $alg_name]
        #[doc = " instance"]
        pub type $name = CoreWrapper<KmacCore<$core>>;
    };
}
