// Copyright 2019-2023 Tauri Programme within The Commons Conservancy
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: MIT

//! [![](https://github.com/tauri-apps/plugins-workspace/raw/v2/plugins/stronghold/banner.png)](https://github.com/tauri-apps/plugins-workspace/tree/v2/plugins/stronghold)
//!
//! Store secrets and keys using the [IOTA Stronghold](https://github.com/iotaledger/stronghold.rs) encrypted database and secure runtime.

#![doc(
    html_logo_url = "https://github.com/tauri-apps/tauri/raw/dev/app-icon.png",
    html_favicon_url = "https://github.com/tauri-apps/tauri/raw/dev/app-icon.png"
)]

use std::{
    collections::HashMap,
    fmt,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

use crypto::keys::bip39::{Mnemonic, Passphrase};
use iota_stronghold::{
    procedures::{
        AleoAuthorize, AleoAuthorizeFeePrivate, AleoAuthorizeFeePublic, AleoExecute, AleoSign,
        AleoSignRequest, BIP39Generate, BIP39Recover, Curve, Ed25519Sign, GetAleoAddress,
        GetAleoViewKey, KeyType as StrongholdKeyType, MnemonicLanguage, PublicKey, Slip10Derive,
        Slip10DeriveInput, Slip10Generate, StrongholdProcedure,
    },
    Client, Location,
};

use serde::{de::Visitor, Deserialize, Deserializer, Serialize};
use snarkvm_console::{
    network::Network,
    program::{Field, Identifier, Plaintext, ProgramID, Record, Value, ValueType},
};
use std::marker::PhantomData;
use stronghold::{Error, Result, Stronghold};
use zeroize::{Zeroize, Zeroizing};

#[cfg(feature = "kdf")]
pub mod kdf;

pub mod stronghold;

type PasswordHashFn = dyn Fn(&str) -> Vec<u8> + Send + Sync;

#[derive(Default)]
pub struct StrongholdCollection(Arc<Mutex<HashMap<PathBuf, Stronghold>>>);

pub struct PasswordHashFunction(pub Box<PasswordHashFn>);

#[derive(Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd, Serialize, Clone)]
#[serde(untagged)]
pub enum BytesDto {
    Text(String),
    Raw(Vec<u8>),
}

impl AsRef<[u8]> for BytesDto {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Text(t) => t.as_ref(),
            Self::Raw(b) => b.as_ref(),
        }
    }
}

impl From<BytesDto> for Vec<u8> {
    fn from(v: BytesDto) -> Self {
        match v {
            BytesDto::Text(t) => t.as_bytes().to_vec(),
            BytesDto::Raw(b) => b,
        }
    }
}

#[derive(Deserialize)]
#[serde(tag = "type", content = "payload")]
pub enum LocationDto {
    Generic { vault: BytesDto, record: BytesDto },
    Counter { vault: BytesDto, counter: usize },
}

impl From<LocationDto> for Location {
    fn from(dto: LocationDto) -> Location {
        match dto {
            LocationDto::Generic { vault, record } => Location::generic(vault, record),
            LocationDto::Counter { vault, counter } => Location::counter(vault, counter),
        }
    }
}

#[derive(Deserialize)]
#[serde(tag = "type", content = "payload")]
#[allow(clippy::upper_case_acronyms)]
pub enum Slip10DeriveInputDto {
    Seed(LocationDto),
    Key(LocationDto),
}

impl From<Slip10DeriveInputDto> for Slip10DeriveInput {
    fn from(dto: Slip10DeriveInputDto) -> Slip10DeriveInput {
        match dto {
            Slip10DeriveInputDto::Seed(location) => Slip10DeriveInput::Seed(location.into()),
            Slip10DeriveInputDto::Key(location) => Slip10DeriveInput::Key(location.into()),
        }
    }
}

pub enum KeyType {
    Ed25519,
    X25519,
}

impl From<KeyType> for StrongholdKeyType {
    fn from(ty: KeyType) -> StrongholdKeyType {
        match ty {
            KeyType::Ed25519 => StrongholdKeyType::Ed25519,
            KeyType::X25519 => StrongholdKeyType::X25519,
        }
    }
}

impl<'de> Deserialize<'de> for KeyType {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct KeyTypeVisitor;

        impl<'de> Visitor<'de> for KeyTypeVisitor {
            type Value = KeyType;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("ed25519 or x25519")
            }

            fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                match value.to_lowercase().as_str() {
                    "ed25519" => Ok(KeyType::Ed25519),
                    "x25519" => Ok(KeyType::X25519),
                    _ => Err(serde::de::Error::custom("unknown key type")),
                }
            }
        }

        deserializer.deserialize_str(KeyTypeVisitor)
    }
}

#[derive(Deserialize)]
#[serde(tag = "type", content = "payload", bound = "N: Network")]
#[allow(clippy::upper_case_acronyms)]
pub enum ProcedureDto<N: Network> {
    SLIP10Generate {
        output: LocationDto,
        #[serde(rename = "sizeBytes")]
        size_bytes: Option<usize>,
    },
    SLIP10Derive {
        curve: Curve,
        chain: Vec<u32>,
        input: Slip10DeriveInputDto,
        output: LocationDto,
        network: String,
    },
    BIP39Recover {
        mnemonic: String,
        passphrase: Option<String>,
        output: LocationDto,
    },
    BIP39Generate {
        passphrase: Option<String>,
        output: LocationDto,
    },
    PublicKey {
        #[serde(rename = "type")]
        ty: KeyType,
        #[serde(rename = "privateKey")]
        private_key: LocationDto,
    },
    Ed25519Sign {
        #[serde(rename = "privateKey")]
        private_key: LocationDto,
        msg: String,
    },
    AleoSign {
        #[serde(rename = "privateKey")]
        private_key: LocationDto,
        msg: String,
        ext: Identifier<N>,
    },
    GetAleoAddress {
        #[serde(rename = "privateKey")]
        private_key: LocationDto,
        ext: Identifier<N>,
    },
    GetAleoViewKey {
        #[serde(rename = "privateKey")]
        private_key: LocationDto,
        _network: PhantomData<N>,
    },
    AleoSignRequest {
        program_id: ProgramID<N>,
        function_name: Identifier<N>,
        inputs: Vec<Value<N>>,
        input_types: Vec<ValueType<N>>,
        root_tvk: Option<Field<N>>,
        is_root: bool,
        #[serde(rename = "privateKey")]
        private_key: LocationDto,
    },
    AleoAuthorize {
        private_key: LocationDto,
        program_id: ProgramID<N>,
        function_name: Identifier<N>,
        inputs: Vec<Value<N>>,
    },
    AleoAuthorizeFeePublic {
        private_key: LocationDto,
        base_fee_in_microcredits: u64,
        priority_fee_in_microcredits: u64,
        deployment_or_execution_id: Field<N>,
    },
    AleoAuthorizeFeePrivate {
        private_key: LocationDto,
        credits: Record<N, Plaintext<N>>,
        base_fee_in_microcredits: u64,
        priority_fee_in_microcredits: u64,
        deployment_or_execution_id: Field<N>,
    },
    AleoExecute {
        #[serde(rename = "privateKey")]
        private_key: LocationDto,
        program_id: ProgramID<N>,
        function_name: Identifier<N>,
        inputs: Vec<Value<N>>,
        fee_record: Option<Record<N, Plaintext<N>>>,
        priority_fee_in_microcredits: u64,
        base_url: String,
    },
}

impl<N: Network> From<ProcedureDto<N>> for StrongholdProcedure<N> {
    fn from(dto: ProcedureDto<N>) -> StrongholdProcedure<N> {
        match dto {
            ProcedureDto::SLIP10Generate { output, size_bytes } => {
                StrongholdProcedure::Slip10Generate(Slip10Generate {
                    output: output.into(),
                    size_bytes,
                })
            }
            ProcedureDto::SLIP10Derive {
                curve,
                chain,
                input,
                output,
                network,
            } => StrongholdProcedure::Slip10Derive(Slip10Derive {
                curve,
                chain,
                input: input.into(),
                output: output.into(),
                network,
            }),
            ProcedureDto::BIP39Recover {
                mnemonic,
                passphrase,
                output,
            } => StrongholdProcedure::BIP39Recover(BIP39Recover {
                mnemonic: Mnemonic::from(mnemonic),
                passphrase: Passphrase::from(passphrase.unwrap_or("".to_string())),
                output: output.into(),
            }),
            ProcedureDto::BIP39Generate { passphrase, output } => {
                StrongholdProcedure::BIP39Generate(BIP39Generate {
                    passphrase: Passphrase::from(passphrase.unwrap_or("".to_string())),
                    output: output.into(),
                    language: MnemonicLanguage::English,
                })
            }
            ProcedureDto::PublicKey { ty, private_key } => {
                StrongholdProcedure::PublicKey(PublicKey {
                    ty: ty.into(),
                    private_key: private_key.into(),
                })
            }
            ProcedureDto::Ed25519Sign { private_key, msg } => {
                StrongholdProcedure::Ed25519Sign(Ed25519Sign {
                    private_key: private_key.into(),
                    msg: msg.as_bytes().to_vec(),
                })
            }
            ProcedureDto::AleoSign {
                private_key,
                msg,
                ext,
            } => StrongholdProcedure::AleoSign(AleoSign {
                private_key: private_key.into(),
                msg: msg.as_bytes().to_vec(),
                ext,
            }),
            ProcedureDto::GetAleoAddress { private_key, ext } => {
                StrongholdProcedure::GetAleoAddress(GetAleoAddress {
                    private_key: private_key.into(),
                    ext,
                })
            }
            ProcedureDto::GetAleoViewKey {
                private_key,
                _network,
            } => StrongholdProcedure::GetAleoViewKey(GetAleoViewKey {
                private_key: private_key.into(),
                _network,
            }),
            ProcedureDto::AleoSignRequest {
                program_id,
                function_name,
                inputs,
                input_types,
                root_tvk,
                is_root,
                private_key,
            } => StrongholdProcedure::AleoSignRequest(AleoSignRequest {
                program_id,
                function_name,
                inputs,
                input_types,
                root_tvk,
                is_root,
                private_key: private_key.into(),
            }),
            ProcedureDto::AleoAuthorize {
                private_key,
                program_id,
                function_name,
                inputs,
            } => StrongholdProcedure::AleoAuthorize(AleoAuthorize {
                private_key: private_key.into(),
                program_id,
                function_name,
                inputs,
            }),
            ProcedureDto::AleoAuthorizeFeePublic {
                private_key,
                base_fee_in_microcredits,
                priority_fee_in_microcredits,
                deployment_or_execution_id,
            } => StrongholdProcedure::AleoAuthorizeFeePublic(AleoAuthorizeFeePublic {
                private_key: private_key.into(),
                base_fee_in_microcredits,
                priority_fee_in_microcredits,
                deployment_or_execution_id,
            }),
            ProcedureDto::AleoAuthorizeFeePrivate {
                private_key,
                credits,
                base_fee_in_microcredits,
                priority_fee_in_microcredits,
                deployment_or_execution_id,
            } => StrongholdProcedure::AleoAuthorizeFeePrivate(AleoAuthorizeFeePrivate {
                private_key: private_key.into(),
                credits,
                base_fee_in_microcredits,
                priority_fee_in_microcredits,
                deployment_or_execution_id,
            }),
            ProcedureDto::AleoExecute {
                private_key,
                program_id,
                function_name,
                inputs,
                fee_record,
                priority_fee_in_microcredits,
                base_url,
            } => StrongholdProcedure::AleoExecute(AleoExecute {
                private_key: private_key.into(),
                program_id,
                function_name,
                inputs,
                fee_record,
                priority_fee_in_microcredits,
                base_url,
            }),
        }
    }
}

pub async fn initialize(
    collection: &StrongholdCollection,
    hash_function: PasswordHashFunction,
    snapshot_path: PathBuf,
    mut password: String,
) -> Result<()> {
    let hash = (hash_function.0)(&password);
    password.zeroize();
    let stronghold = Stronghold::new(snapshot_path.clone(), hash)?;

    collection
        .0
        .lock()
        .unwrap()
        .insert(snapshot_path, stronghold);

    Ok(())
}

pub async fn destroy(collection: &StrongholdCollection, snapshot_path: PathBuf) -> Result<()> {
    let mut collection = collection.0.lock().unwrap();
    if let Some(stronghold) = collection.remove(&snapshot_path) {
        if let Err(e) = stronghold.save() {
            collection.insert(snapshot_path, stronghold);
            return Err(e);
        }
    }
    Ok(())
}

pub async fn save(collection: &StrongholdCollection, snapshot_path: PathBuf) -> Result<()> {
    let collection = collection.0.lock().unwrap();
    if let Some(stronghold) = collection.get(&snapshot_path) {
        stronghold.save()?;
    }
    Ok(())
}

pub async fn create_client(
    collection: &StrongholdCollection,
    snapshot_path: PathBuf,
    client: BytesDto,
) -> Result<()> {
    let stronghold = get_stronghold(collection, snapshot_path)?;
    stronghold.create_client(client)?;
    Ok(())
}

pub async fn load_client(
    collection: &StrongholdCollection,
    snapshot_path: PathBuf,
    client: BytesDto,
) -> Result<()> {
    let stronghold = get_stronghold(collection, snapshot_path)?;
    stronghold.load_client(client)?;
    Ok(())
}

pub async fn get_store_record(
    collection: &StrongholdCollection,
    snapshot_path: PathBuf,
    client: BytesDto,
    key: String,
) -> Result<Option<Vec<u8>>> {
    let client = get_client(collection, snapshot_path, client)?;
    client.store().get(key.as_ref()).map_err(Into::into)
}

pub async fn save_store_record(
    collection: &StrongholdCollection,
    snapshot_path: PathBuf,
    client: BytesDto,
    key: String,
    value: Vec<u8>,
    lifetime: Option<Duration>,
) -> Result<Option<Vec<u8>>> {
    let client = get_client(collection, snapshot_path, client)?;
    client
        .store()
        .insert(key.as_bytes().to_vec(), value, lifetime)
        .map_err(Into::into)
}

pub async fn remove_store_record(
    collection: &StrongholdCollection,
    snapshot_path: PathBuf,
    client: BytesDto,
    key: String,
) -> Result<Option<Vec<u8>>> {
    let client = get_client(collection, snapshot_path, client)?;
    client.store().delete(key.as_ref()).map_err(Into::into)
}

pub async fn save_secret(
    collection: &StrongholdCollection,
    snapshot_path: PathBuf,
    client: BytesDto,
    vault: BytesDto,
    record_path: BytesDto,
    secret: Vec<u8>,
) -> Result<()> {
    let client = get_client(collection, snapshot_path, client)?;
    client
        .vault(&vault)
        .write_secret(
            Location::generic(vault, record_path),
            zeroize::Zeroizing::new(secret),
        )
        .map_err(Into::into)
}

pub async fn unsafe_get_secret(
    collection: &StrongholdCollection,
    snapshot_path: PathBuf,
    client: BytesDto,
    vault: BytesDto,
    record_path: BytesDto,
) -> Result<Zeroizing<Vec<u8>>> {
    let client = get_client(collection, snapshot_path, client)?;
    client
        .vault(&vault)
        .read_secret(record_path)
        .map_err(Into::into)
}

pub async fn remove_secret(
    collection: &StrongholdCollection,
    snapshot_path: PathBuf,
    client: BytesDto,
    vault: BytesDto,
    record_path: BytesDto,
) -> Result<()> {
    let client = get_client(collection, snapshot_path, client)?;
    client
        .vault(vault)
        .delete_secret(record_path)
        .map(|_| ())
        .map_err(Into::into)
}

pub async fn execute_procedure<N: Network>(
    collection: &StrongholdCollection,
    snapshot_path: PathBuf,
    client: BytesDto,
    procedure: ProcedureDto<N>,
) -> Result<Vec<u8>> {
    let client = get_client(collection, snapshot_path, client)?;
    client
        .execute_procedure(StrongholdProcedure::from(procedure))
        .map(Into::into)
        .map_err(Into::into)
}

fn get_stronghold(
    collection: &StrongholdCollection,
    snapshot_path: PathBuf,
) -> Result<iota_stronghold::Stronghold> {
    let collection = collection.0.lock().unwrap();
    if let Some(stronghold) = collection.get(&snapshot_path) {
        Ok(stronghold.inner().clone())
    } else {
        Err(Error::StrongholdNotInitialized)
    }
}

fn get_client(
    collection: &StrongholdCollection,
    snapshot_path: PathBuf,
    client: BytesDto,
) -> Result<Client> {
    let collection = collection.0.lock().unwrap();
    if let Some(stronghold) = collection.get(&snapshot_path) {
        stronghold.get_client(client).map_err(Into::into)
    } else {
        Err(Error::StrongholdNotInitialized)
    }
}

pub enum PasswordHashFunctionKind {
    #[cfg(feature = "kdf")]
    Argon2(PathBuf),
    Custom(Box<PasswordHashFn>),
}
