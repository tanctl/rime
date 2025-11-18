use std::{io::Cursor, str::FromStr};

use orchard::{keys::FullViewingKey as OrchardFullViewingKey, Address as OrchardAddress};
use sapling::{zip32::ExtendedFullViewingKey, PaymentAddress};
use subtle::CtOption;
use zcash_address::{
    unified::{self, Container, Encoding, Fvk as UnifiedFvk, ParseError, Ufvk},
    Network as UnifiedNetwork,
};

use crate::{Error, Network};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransparentReceiver {
    P2pkh([u8; 20]),
    P2sh([u8; 20]),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnifiedReceiver {
    Transparent(TransparentReceiver),
    Sapling(PaymentAddress),
    Orchard(OrchardAddress),
}

impl UnifiedReceiver {
    fn into_unified(self) -> unified::Receiver {
        match self {
            UnifiedReceiver::Transparent(TransparentReceiver::P2pkh(bytes)) => {
                unified::Receiver::P2pkh(bytes)
            }
            UnifiedReceiver::Transparent(TransparentReceiver::P2sh(bytes)) => {
                unified::Receiver::P2sh(bytes)
            }
            UnifiedReceiver::Sapling(addr) => unified::Receiver::Sapling(addr.to_bytes()),
            UnifiedReceiver::Orchard(addr) => {
                unified::Receiver::Orchard(addr.to_raw_address_bytes())
            }
        }
    }
}

impl TryFrom<unified::Receiver> for UnifiedReceiver {
    type Error = Error;

    fn try_from(value: unified::Receiver) -> Result<Self, Self::Error> {
        match value {
            unified::Receiver::Sapling(bytes) => PaymentAddress::from_bytes(&bytes)
                .map(UnifiedReceiver::Sapling)
                .ok_or_else(|| Error::InvalidData("invalid sapling receiver bytes".into())),
            unified::Receiver::Orchard(bytes) => {
                let parsed: CtOption<OrchardAddress> =
                    OrchardAddress::from_raw_address_bytes(&bytes);
                Option::<OrchardAddress>::from(parsed)
                    .map(UnifiedReceiver::Orchard)
                    .ok_or_else(|| Error::InvalidData("invalid orchard receiver bytes".into()))
            }
            unified::Receiver::P2pkh(bytes) => Ok(UnifiedReceiver::Transparent(
                TransparentReceiver::P2pkh(bytes),
            )),
            unified::Receiver::P2sh(bytes) => Ok(UnifiedReceiver::Transparent(
                TransparentReceiver::P2sh(bytes),
            )),
            unified::Receiver::Unknown { typecode, .. } => Err(Error::InvalidData(format!(
                "unknown unified receiver typecode {typecode}"
            ))),
        }
    }
}

#[derive(Debug, Clone)]
pub struct UnifiedAddress {
    network: UnifiedNetwork,
    inner: unified::Address,
}

impl UnifiedAddress {
    pub fn from_encoded(value: &str) -> Result<Self, Error> {
        let (network, inner) =
            unified::Address::decode(value).map_err(|err| Error::InvalidData(err.to_string()))?;
        Ok(Self { network, inner })
    }

    pub fn from_receivers(
        network: Network,
        receivers: Vec<UnifiedReceiver>,
    ) -> Result<Self, Error> {
        let items: Vec<_> = receivers
            .into_iter()
            .map(UnifiedReceiver::into_unified)
            .collect();
        let inner = unified::Address::try_from_items(items)
            .map_err(|err: ParseError| Error::InvalidData(err.to_string()))?;
        Ok(Self {
            network: network_to_address_network(network),
            inner,
        })
    }

    pub fn sapling_receiver(&self) -> Option<PaymentAddress> {
        self.inner.items().iter().find_map(|receiver| {
            if let unified::Receiver::Sapling(bytes) = receiver {
                PaymentAddress::from_bytes(bytes)
            } else {
                None
            }
        })
    }

    pub fn orchard_receiver(&self) -> Option<OrchardAddress> {
        self.inner.items().iter().find_map(|receiver| {
            if let unified::Receiver::Orchard(bytes) = receiver {
                OrchardAddress::from_raw_address_bytes(bytes).into()
            } else {
                None
            }
        })
    }

    #[allow(clippy::inherent_to_string)]
    pub fn to_string(&self) -> String {
        self.inner.encode(&self.network)
    }
}

impl FromStr for UnifiedAddress {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        UnifiedAddress::from_encoded(s)
    }
}

#[derive(Debug, Clone)]
pub struct UnifiedFullViewingKey {
    network: Network,
    pub sapling: Option<ExtendedFullViewingKey>,
    pub orchard: Option<OrchardFullViewingKey>,
}

impl UnifiedFullViewingKey {
    pub fn from_components(
        network: Network,
        sapling: Option<ExtendedFullViewingKey>,
        orchard: Option<OrchardFullViewingKey>,
    ) -> Self {
        Self {
            network,
            sapling,
            orchard,
        }
    }

    pub fn network(&self) -> Network {
        self.network
    }

    pub fn encode_uview(&self) -> Result<String, Error> {
        let mut items = Vec::new();
        if let Some(sapling) = &self.sapling {
            let dfvk = sapling.to_diversifiable_full_viewing_key();
            items.push(UnifiedFvk::Sapling(dfvk.to_bytes()));
        }
        if let Some(orchard) = &self.orchard {
            items.push(UnifiedFvk::Orchard(orchard.to_bytes()));
        }
        if items.is_empty() {
            return Err(Error::InvalidData(
                "unified viewing key missing shielded components".into(),
            ));
        }
        items.sort_by_key(typecode_for_fvk_component);
        let ufvk =
            Ufvk::try_from_items(items).map_err(|err| Error::InvalidData(err.to_string()))?;
        Ok(ufvk.encode(&network_to_address_network(self.network)))
    }

    pub fn decode_uview(encoded: &str) -> Result<Self, Error> {
        let (network, ufvk) =
            Ufvk::decode(encoded).map_err(|err| Error::InvalidData(err.to_string()))?;
        let mut sapling = None;
        let mut orchard = None;
        for item in ufvk.items() {
            match item {
                UnifiedFvk::Sapling(bytes) => sapling = Some(parse_sapling_fvk(bytes)?),
                UnifiedFvk::Orchard(bytes) => {
                    let parsed = OrchardFullViewingKey::from_bytes(&bytes)
                        .ok_or_else(|| Error::InvalidData("invalid Orchard FVK bytes".into()))?;
                    orchard = Some(parsed);
                }
                UnifiedFvk::P2pkh(_) => {}
                UnifiedFvk::Unknown { typecode, .. } => {
                    return Err(Error::InvalidData(format!(
                        "unknown UFVK component typecode {typecode}"
                    )))
                }
            }
        }

        if sapling.is_none() && orchard.is_none() {
            return Err(Error::InvalidData(
                "unified viewing key missing shielded components".into(),
            ));
        }

        Ok(Self {
            network: network_from_address_network(network)?,
            sapling,
            orchard,
        })
    }
}

fn typecode_for_fvk_component(component: &UnifiedFvk) -> u8 {
    match component {
        UnifiedFvk::P2pkh(_) => 0x00,
        UnifiedFvk::Sapling(_) => 0x02,
        UnifiedFvk::Orchard(_) => 0x03,
        UnifiedFvk::Unknown { typecode, .. } => *typecode as u8,
    }
}

fn parse_sapling_fvk(bytes: [u8; 128]) -> Result<ExtendedFullViewingKey, Error> {
    // reconstruct the extended FVK encoding expected by sapling-crypto from the UFVK’s sapling component
    let mut encoding = Vec::with_capacity(169);
    encoding.push(0);
    encoding.extend_from_slice(&[0u8; 4]);
    encoding.extend_from_slice(&0u32.to_le_bytes());
    encoding.extend_from_slice(&[0u8; 32]);
    encoding.extend_from_slice(&bytes[..96]);
    encoding.extend_from_slice(&bytes[96..]);
    ExtendedFullViewingKey::read(Cursor::new(encoding))
        .map_err(|err| Error::InvalidData(format!("invalid sapling UFVK: {err}")))
}

fn network_to_address_network(network: Network) -> UnifiedNetwork {
    match network {
        Network::Mainnet => UnifiedNetwork::Main,
        Network::Testnet => UnifiedNetwork::Test,
    }
}

fn network_from_address_network(network: UnifiedNetwork) -> Result<Network, Error> {
    match network {
        UnifiedNetwork::Main => Ok(Network::Mainnet),
        UnifiedNetwork::Test => Ok(Network::Testnet),
        UnifiedNetwork::Regtest => Err(Error::InvalidData(
            "regtest unified values are unsupported".into(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sapling::zip32::ExtendedSpendingKey;
    use std::str::FromStr;
    use zip32::ChildIndex;

    fn example_sapling_fvk() -> ExtendedFullViewingKey {
        let master = ExtendedSpendingKey::master(&[0u8; 32]);
        let derived = ExtendedSpendingKey::from_path(
            &master,
            &[ChildIndex::hardened(0), ChildIndex::hardened(0)],
        );
        #[allow(deprecated)]
        derived.to_extended_full_viewing_key()
    }

    #[test]
    fn ufvk_round_trip() {
        let sapling = example_sapling_fvk();
        let ufvk =
            UnifiedFullViewingKey::from_components(Network::Mainnet, Some(sapling.clone()), None);
        let encoded = ufvk.encode_uview().expect("encode");
        let decoded = UnifiedFullViewingKey::decode_uview(&encoded).expect("decode");
        assert_eq!(decoded.network(), Network::Mainnet);
        assert!(decoded.sapling.is_some());
        assert!(decoded.orchard.is_none());
    }

    #[test]
    fn unified_address_parse_and_render() {
        let encoded = "u1pg2aaph7jp8rpf6yhsza25722sg5fcn3vaca6ze27hqjw7jvvhhuxkpcg0ge9xh6drsgdkda8qjq5chpehkcpxf87rnjryjqwymdheptpvnljqqrjqzjwkc2ma6hcq666kgwfytxwac8eyex6ndgr6ezte66706e3vaqrd25dzvzkc69kw0jgywtd0cmq52q5lkw6uh7hyvzjse8ksx";
        let ua = UnifiedAddress::from_str(encoded).expect("parse");
        assert!(ua.sapling_receiver().is_some());
        assert!(ua.orchard_receiver().is_some());
        assert_eq!(ua.to_string(), encoded);
    }

    #[test]
    fn ufvk_enforces_and_emits_canonical_order() {
        let sapling = example_sapling_fvk();
        let ufvk =
            UnifiedFullViewingKey::from_components(Network::Mainnet, Some(sapling.clone()), None);
        let encoded = ufvk.encode_uview().expect("encode");
        let decoded = UnifiedFullViewingKey::decode_uview(&encoded).expect("decode");
        assert!(decoded.sapling.is_some());
        assert!(decoded.orchard.is_none());

        // craft an out-of-order ufvk: orchard first, sapling second
        let items = vec![
            UnifiedFvk::Orchard([0u8; 96]),
            UnifiedFvk::Sapling(sapling.to_diversifiable_full_viewing_key().to_bytes()),
        ];
        let ufvk_bad = Ufvk::try_from_items(items).expect("ufvk items");
        let encoded_bad = ufvk_bad.encode(&network_to_address_network(Network::Mainnet));
        assert!(
            UnifiedFullViewingKey::decode_uview(&encoded_bad).is_err(),
            "out-of-order ufvk should be rejected"
        );
    }
}
