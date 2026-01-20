use alloc::vec::Vec;
use core::fmt::Debug;

use crate::server;

/// Something which never stores sessions.
#[expect(clippy::exhaustive_structs)]
#[derive(Debug)]
pub struct NoServerSessionStorage {}

impl server::StoresServerSessions for NoServerSessionStorage {
    fn put(&self, _id: Vec<u8>, _sec: Vec<u8>) -> bool {
        false
    }
    fn get(&self, _id: &[u8]) -> Option<Vec<u8>> {
        None
    }
    fn take(&self, _id: &[u8]) -> Option<Vec<u8>> {
        None
    }
    fn can_cache(&self) -> bool {
        false
    }
}

#[cfg(any(feature = "std", feature = "hashbrown"))]
mod cache {
    use alloc::vec::Vec;
    use core::fmt::{Debug, Formatter};
    use core::hash::BuildHasher;
    #[cfg(feature = "std")]
    use std::hash::RandomState;

    #[cfg(not(feature = "std"))]
    use hashbrown::DefaultHashBuilder as RandomState;

    use crate::lock::Mutex;
    use crate::sync::Arc;
    use crate::{limited_cache, server};

    const SHARED_COUNT: usize = 2;

    /// An implementer of `StoresServerSessions` that stores everything
    /// in memory.  If enforces a limit on the number of stored sessions
    /// to bound memory usage.
    pub struct ServerSessionMemoryCache {
        hash_builder: RandomState,
        cache: [Mutex<limited_cache::LimitedCache<Vec<u8>, Vec<u8>>>; SHARED_COUNT],
    }

    impl ServerSessionMemoryCache {
        /// Make a new ServerSessionMemoryCache.  `size` is the maximum
        /// number of stored sessions, and may be rounded-up for
        /// efficiency.
        #[cfg(feature = "std")]
        pub fn new(size: usize) -> Arc<Self> {
            Arc::new(Self {
                hash_builder: RandomState::new(),
                cache: core::array::from_fn(|_| {
                    Mutex::new(limited_cache::LimitedCache::new(size / SHARED_COUNT))
                }),
            })
        }

        /// Make a new ServerSessionMemoryCache.  `size` is the maximum
        /// number of stored sessions, and may be rounded-up for
        /// efficiency.
        #[cfg(not(feature = "std"))]
        pub fn new<M: crate::lock::MakeMutex>(size: usize) -> Arc<Self> {
            Arc::new(Self {
                hash_builder: RandomState::default(),
                cache: core::array::from_fn(|_| {
                    M::new_mutex(limited_cache::LimitedCache::new(max(
                        1,
                        size / SHARED_COUNT,
                    )))
                }),
            })
        }

        /// Which shared cache to use for a given key.
        /// This is used to shard the cache to reduce lock contention.
        pub fn shared_for(&self, key: &[u8]) -> usize {
            (self.hash_builder.hash_one(key) as usize) & (SHARED_COUNT - 1)
        }
    }

    impl server::StoresServerSessions for ServerSessionMemoryCache {
        fn put(&self, key: Vec<u8>, value: Vec<u8>) -> bool {
            let index = self.shared_for(&key);
            if let Some(mut cache) = self.cache[index].try_lock() {
                cache.insert(key, value);
                true
            } else {
                false
            }
        }

        fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
            let index = self.shared_for(key);
            self.cache[index]
                .try_lock()?
                .get(key)
                .cloned()
        }

        fn take(&self, key: &[u8]) -> Option<Vec<u8>> {
            let index = self.shared_for(key);
            self.cache[index]
                .try_lock()?
                .remove(key)
        }

        fn can_cache(&self) -> bool {
            true
        }
    }

    impl Debug for ServerSessionMemoryCache {
        fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
            f.debug_struct("ServerSessionMemoryCache")
                .finish()
        }
    }

    #[cfg(test)]
    mod tests {
        use std::vec;

        use super::*;
        use crate::server::StoresServerSessions;

        #[test]
        fn test_serversessionmemorycache_accepts_put() {
            let c = ServerSessionMemoryCache::new(4);
            assert!(c.put(vec![0x01], vec![0x02]));
        }

        #[test]
        fn test_serversessionmemorycache_persists_put() {
            let c = ServerSessionMemoryCache::new(4);
            assert!(c.put(vec![0x01], vec![0x02]));
            assert_eq!(c.get(&[0x01]), Some(vec![0x02]));
            assert_eq!(c.get(&[0x01]), Some(vec![0x02]));
        }

        #[test]
        fn test_serversessionmemorycache_overwrites_put() {
            let c = ServerSessionMemoryCache::new(4);
            assert!(c.put(vec![0x01], vec![0x02]));
            assert!(c.put(vec![0x01], vec![0x04]));
            assert_eq!(c.get(&[0x01]), Some(vec![0x04]));
        }

        #[test]
        fn test_serversessionmemorycache_drops_to_maintain_size_invariant() {
            let c = ServerSessionMemoryCache::new(2);
            assert!(c.put(vec![0x01], vec![0x02]));
            assert!(c.put(vec![0x03], vec![0x04]));
            assert!(c.put(vec![0x05], vec![0x06]));
            assert!(c.put(vec![0x07], vec![0x08]));
            assert!(c.put(vec![0x09], vec![0x0a]));

            let count = c.get(&[0x01]).iter().count()
                + c.get(&[0x03]).iter().count()
                + c.get(&[0x05]).iter().count()
                + c.get(&[0x07]).iter().count()
                + c.get(&[0x09]).iter().count();

            assert!(count < 5);
        }

        #[test]
        fn test_serversessionmemorycache_drops_to_maintain_size_invariant_many() {
            let c = ServerSessionMemoryCache::new(32);
            for i in 0..32u8 {
                c.put(vec![i], vec![i]);
            }

            let mut count = 0;
            for i in 0..32u8 {
                if c.get(&[i]).is_some() {
                    count += 1;
                }
            }

            assert!(count < 32);
        }
    }
}

#[cfg(any(feature = "std", feature = "hashbrown"))]
pub use cache::ServerSessionMemoryCache;

#[cfg(any(feature = "std", feature = "hashbrown"))]
mod sni_resolver {
    use core::fmt::Debug;

    use pki_types::{DnsName, ServerName};

    use crate::crypto::{CertificateIdentity, Credentials, Identity, SelectedCredential};
    use crate::error::{Error, PeerIncompatible};
    use crate::hash_map::HashMap;
    use crate::server::{self, ClientHello};
    use crate::sync::Arc;
    use crate::webpki::{ParsedCertificate, verify_server_name};

    /// Something that resolves do different cert chains/keys based
    /// on client-supplied server name (via SNI).
    #[derive(Debug)]
    pub struct ServerNameResolver {
        by_name: HashMap<DnsName<'static>, Arc<Credentials>>,
    }

    impl ServerNameResolver {
        /// Create a new and empty (i.e., knows no certificates) resolver.
        pub fn new() -> Self {
            Self {
                by_name: HashMap::new(),
            }
        }

        /// Add a new `Credentials` to be used for the given SNI `name`.
        ///
        /// This function fails if the `name` is not valid for the supplied certificate, or if
        /// the certificate chain is syntactically faulty.
        pub fn add(&mut self, name: DnsName<'static>, ck: Credentials) -> Result<(), Error> {
            // Check the certificate chain for validity:
            // - it should be non-empty list
            // - the first certificate should be parsable as a x509v3,
            // - the first certificate should quote the given server name
            //   (if provided)
            //
            // These checks are not security-sensitive.  They are the
            // *server* attempting to detect accidental misconfiguration.

            let wrapped = ServerName::DnsName(name);
            if let Identity::X509(CertificateIdentity { end_entity, .. }) = &*ck.identity {
                let parsed = ParsedCertificate::try_from(end_entity)?;
                verify_server_name(&parsed, &wrapped)?;
            }

            let ServerName::DnsName(name) = wrapped else {
                unreachable!()
            };

            self.by_name.insert(name, Arc::new(ck));
            Ok(())
        }
    }

    impl server::ServerCredentialResolver for ServerNameResolver {
        fn resolve(&self, client_hello: &ClientHello<'_>) -> Result<SelectedCredential, Error> {
            let Some(name) = client_hello.server_name() else {
                return Err(PeerIncompatible::NoServerNameProvided.into());
            };

            let Some(credentials) = self.by_name.get(name) else {
                return Err(Error::NoSuitableCertificate);
            };

            match credentials.signer(client_hello.signature_schemes) {
                Some(signer) => Ok(signer),
                None => Err(PeerIncompatible::NoSignatureSchemesInCommon.into()),
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use alloc::borrow::Cow;

        use super::*;
        use crate::server::ServerCredentialResolver;

        #[test]
        fn test_server_name_resolver_requires_sni() {
            let rscsni = ServerNameResolver::new();
            assert!(
                rscsni
                    .resolve(&ClientHello {
                        server_name: None,
                        signature_schemes: &[],
                        alpn: None,
                        server_cert_types: None,
                        client_cert_types: None,
                        cipher_suites: &[],
                        certificate_authorities: None,
                        named_groups: None,
                    })
                    .is_err()
            );
        }

        #[test]
        fn test_server_name_resolver_handles_unknown_name() {
            let rscsni = ServerNameResolver::new();
            let name = DnsName::try_from("hello.com")
                .unwrap()
                .to_owned();
            assert!(
                rscsni
                    .resolve(&ClientHello {
                        server_name: Some(Cow::Borrowed(&name)),
                        signature_schemes: &[],
                        alpn: None,
                        server_cert_types: None,
                        client_cert_types: None,
                        cipher_suites: &[],
                        certificate_authorities: None,
                        named_groups: None,
                    })
                    .is_err()
            );
        }
    }
}

#[cfg(any(feature = "std", feature = "hashbrown"))]
pub use sni_resolver::ServerNameResolver;

#[cfg(test)]
mod tests {
    use std::vec;

    use super::*;
    use crate::server::StoresServerSessions;

    #[test]
    fn test_noserversessionstorage_drops_put() {
        let c = NoServerSessionStorage {};
        assert!(!c.put(vec![0x01], vec![0x02]));
    }

    #[test]
    fn test_noserversessionstorage_denies_gets() {
        let c = NoServerSessionStorage {};
        c.put(vec![0x01], vec![0x02]);
        assert_eq!(c.get(&[]), None);
        assert_eq!(c.get(&[0x01]), None);
        assert_eq!(c.get(&[0x02]), None);
    }

    #[test]
    fn test_noserversessionstorage_denies_takes() {
        let c = NoServerSessionStorage {};
        assert_eq!(c.take(&[]), None);
        assert_eq!(c.take(&[0x01]), None);
        assert_eq!(c.take(&[0x02]), None);
    }
}
