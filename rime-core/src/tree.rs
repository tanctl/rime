use incrementalmerkletree::{
    frontier::CommitmentTree, witness::IncrementalWitness, Hashable, Level,
};
use lazy_static::lazy_static;
use orchard::{tree::MerkleHashOrchard, NOTE_COMMITMENT_TREE_DEPTH as ORCHARD_NOTE_DEPTH_USIZE};
use sapling::{merkle_hash, Node as SaplingNodeInner, NOTE_COMMITMENT_TREE_DEPTH};
use serde::{Deserialize, Serialize};
use std::{
    convert::TryFrom,
    io::{Cursor, Read, Write},
};
use thiserror::Error;
use zcash_primitives::merkle_tree::{
    read_commitment_tree, read_incremental_witness, write_commitment_tree,
    write_incremental_witness, HashSer,
};

use crate::{notes::Pool, Error};

const SAPLING_TREE_DEPTH: u8 = NOTE_COMMITMENT_TREE_DEPTH;
const ORCHARD_TREE_DEPTH: u8 = ORCHARD_NOTE_DEPTH_USIZE as u8;

lazy_static! {
    static ref UNCOMMITTED_LEAF: [u8; 32] = <SaplingNodeInner as Hashable>::empty_leaf().to_bytes();
    static ref EMPTY_ROOTS: Vec<[u8; 32]> = {
        let mut roots = Vec::with_capacity((SAPLING_TREE_DEPTH + 1) as usize);
        roots.push(*UNCOMMITTED_LEAF);
        for depth in 0..SAPLING_TREE_DEPTH {
            let prev = roots[depth as usize];
            roots.push(merkle_hash(depth as usize, &prev, &prev));
        }
        roots
    };
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SaplingNode(pub [u8; 32]);

impl SaplingNode {
    fn into_bytes(self) -> [u8; 32] {
        self.0
    }

    fn as_inner(&self) -> Result<SaplingNodeInner, Error> {
        SaplingNodeInner::from_bytes(self.0)
            .into_option()
            .ok_or_else(|| Error::InvalidData("invalid sapling node bytes".into()))
    }
}

impl From<[u8; 32]> for SaplingNode {
    fn from(value: [u8; 32]) -> Self {
        SaplingNode(value)
    }
}

impl Hashable for SaplingNode {
    fn empty_leaf() -> Self {
        SaplingNode(*UNCOMMITTED_LEAF)
    }

    fn combine(level: Level, left: &Self, right: &Self) -> Self {
        let out = merkle_hash(level.into(), &left.0, &right.0);
        SaplingNode(out)
    }

    fn empty_root(level: Level) -> Self {
        let idx = usize::from(u8::from(level));
        SaplingNode(EMPTY_ROOTS[idx])
    }
}

impl HashSer for SaplingNode {
    fn read<R: Read>(mut reader: R) -> std::io::Result<Self> {
        let mut bytes = [0u8; 32];
        reader.read_exact(&mut bytes)?;
        Ok(SaplingNode(bytes))
    }

    fn write<W: Write>(&self, mut writer: W) -> std::io::Result<()> {
        writer.write_all(&self.0)
    }
}

#[derive(Debug, Error)]
pub enum TreeError {
    #[error("tree is empty")]
    Empty,
    #[error("serialization: {0}")]
    Serialization(String),
    #[error("witness for position {0} not found")]
    MissingWitness(u64),
    #[error("witness for position {0} is invalid")]
    InvalidWitness(u64),
    #[error("internal error: {0}")]
    Internal(String),
}

pub struct NoteCommitmentTree {
    tree: CommitmentTree<SaplingNode, { SAPLING_TREE_DEPTH }>,
    leaves: Vec<SaplingNode>,
}

pub struct OrchardNoteCommitmentTree {
    tree: CommitmentTree<MerkleHashOrchard, { ORCHARD_TREE_DEPTH }>,
    leaves: Vec<MerkleHashOrchard>,
}

pub enum PoolTree {
    Sapling(NoteCommitmentTree),
    Orchard(OrchardNoteCommitmentTree),
}

#[derive(Clone, Serialize, Deserialize)]
pub struct TreeCheckpoint {
    pub height: u32,
    pub pool: Pool,
    pub root: [u8; 32],
    pub tree_state: Vec<u8>,
}

impl Default for NoteCommitmentTree {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for OrchardNoteCommitmentTree {
    fn default() -> Self {
        Self::new()
    }
}

impl NoteCommitmentTree {
    pub fn new() -> Self {
        Self {
            tree: CommitmentTree::empty(),
            leaves: Vec::new(),
        }
    }

    pub fn append(&mut self, commitment: [u8; 32]) -> Result<u64, Error> {
        let node = SaplingNode(commitment);
        self.tree
            .append(node)
            .map_err(|_| TreeError::Internal("tree full".into()))?;
        self.leaves.push(node);
        Ok(self.size().saturating_sub(1))
    }

    pub fn root(&self) -> Result<[u8; 32], Error> {
        if self.size() == 0 {
            return Err(TreeError::Empty.into());
        }
        Ok(self.tree.root().into_bytes())
    }

    pub fn size(&self) -> u64 {
        self.leaves.len() as u64
    }

    pub fn witness_for_position(&self, pos: u64) -> Result<Vec<u8>, Error> {
        let index = usize::try_from(pos).map_err(|_| TreeError::MissingWitness(pos))?;
        if index >= self.leaves.len() {
            return Err(TreeError::MissingWitness(pos).into());
        }
        let witness = self.build_witness(index)?;
        serialize_witness_generic(&witness)
    }

    pub fn verify_witness(&self, position: u64, encoded: &[u8]) -> Result<(), Error> {
        let witness = deserialize_witness_generic::<SaplingNode, { SAPLING_TREE_DEPTH }>(encoded)?;
        if u64::from(witness.witnessed_position()) != position {
            return Err(TreeError::InvalidWitness(position).into());
        }
        let expected = self.root()?;
        if witness.root().into_bytes() == expected {
            Ok(())
        } else {
            Err(TreeError::InvalidWitness(position).into())
        }
    }

    pub fn serialize(&self) -> Result<Vec<u8>, Error> {
        let payload = PersistedTree {
            tree: serialize_tree_generic(&self.tree)?,
            leaves: self.leaves.iter().map(|node| node.0).collect(),
        };
        bincode::serialize(&payload).map_err(|e| TreeError::Serialization(e.to_string()).into())
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, Error> {
        let payload: PersistedTree =
            bincode::deserialize(data).map_err(|e| TreeError::Serialization(e.to_string()))?;
        let tree = deserialize_tree_generic::<SaplingNode, { SAPLING_TREE_DEPTH }>(&payload.tree)?;
        let leaves = payload.leaves.into_iter().map(SaplingNode::from).collect();
        Ok(Self { tree, leaves })
    }

    pub fn checkpoint(&self, pool: Pool, height: u32) -> Result<TreeCheckpoint, Error> {
        Ok(TreeCheckpoint {
            height,
            pool,
            root: self.root()?,
            tree_state: self.serialize()?,
        })
    }

    pub fn restore(checkpoint: &TreeCheckpoint) -> Result<Self, Error> {
        Self::deserialize(&checkpoint.tree_state)
    }

    fn build_witness(
        &self,
        index: usize,
    ) -> Result<IncrementalWitness<SaplingNode, { SAPLING_TREE_DEPTH }>, Error> {
        let mut working_tree = CommitmentTree::empty();
        let mut witness = None;
        for (i, node) in self.leaves.iter().enumerate() {
            working_tree
                .append(*node)
                .map_err(|_| TreeError::Internal("tree full".into()))?;
            if i == index {
                witness = Some(
                    IncrementalWitness::from_tree(working_tree.clone())
                        .expect("witness generation should succeed"),
                );
            } else if let Some(w) = witness.as_mut() {
                w.append(*node)
                    .map_err(|_| TreeError::Internal("unable to extend witness".into()))?;
            }
        }
        witness.ok_or_else(|| TreeError::MissingWitness(index as u64).into())
    }
}

impl OrchardNoteCommitmentTree {
    pub fn new() -> Self {
        Self {
            tree: CommitmentTree::empty(),
            leaves: Vec::new(),
        }
    }

    pub fn append(&mut self, commitment: [u8; 32]) -> Result<u64, Error> {
        let node = MerkleHashOrchard::from_bytes(&commitment)
            .into_option()
            .ok_or_else(|| Error::InvalidData("invalid orchard commitment bytes".into()))?;
        self.tree
            .append(node)
            .map_err(|_| TreeError::Internal("tree full".into()))?;
        self.leaves.push(node);
        Ok(self.size().saturating_sub(1))
    }

    pub fn root(&self) -> Result<[u8; 32], Error> {
        if self.size() == 0 {
            return Err(TreeError::Empty.into());
        }
        Ok(self.tree.root().to_bytes())
    }

    pub fn size(&self) -> u64 {
        self.leaves.len() as u64
    }

    pub fn witness_for_position(&self, pos: u64) -> Result<Vec<u8>, Error> {
        let index = usize::try_from(pos).map_err(|_| TreeError::MissingWitness(pos))?;
        if index >= self.leaves.len() {
            return Err(TreeError::MissingWitness(pos).into());
        }
        let witness = self.build_witness(index)?;
        serialize_witness_generic(&witness)
    }

    pub fn verify_witness(&self, position: u64, encoded: &[u8]) -> Result<(), Error> {
        let witness =
            deserialize_witness_generic::<MerkleHashOrchard, { ORCHARD_TREE_DEPTH }>(encoded)?;
        if u64::from(witness.witnessed_position()) != position {
            return Err(TreeError::InvalidWitness(position).into());
        }
        let expected = self.root()?;
        if witness.root().to_bytes() == expected {
            Ok(())
        } else {
            Err(TreeError::InvalidWitness(position).into())
        }
    }

    pub fn serialize(&self) -> Result<Vec<u8>, Error> {
        let payload = PersistedTree {
            tree: serialize_tree_generic(&self.tree)?,
            leaves: self.leaves.iter().map(|leaf| leaf.to_bytes()).collect(),
        };
        bincode::serialize(&payload).map_err(|e| TreeError::Serialization(e.to_string()).into())
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, Error> {
        let payload: PersistedTree =
            bincode::deserialize(data).map_err(|e| TreeError::Serialization(e.to_string()))?;
        let tree =
            deserialize_tree_generic::<MerkleHashOrchard, { ORCHARD_TREE_DEPTH }>(&payload.tree)?;
        let leaves = payload
            .leaves
            .into_iter()
            .map(|bytes| {
                MerkleHashOrchard::from_bytes(&bytes)
                    .into_option()
                    .ok_or_else(|| Error::InvalidData("invalid orchard node bytes".into()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self { tree, leaves })
    }

    pub fn checkpoint(&self, height: u32) -> Result<TreeCheckpoint, Error> {
        Ok(TreeCheckpoint {
            height,
            pool: Pool::Orchard,
            root: self.root()?,
            tree_state: self.serialize()?,
        })
    }

    pub fn restore(checkpoint: &TreeCheckpoint) -> Result<Self, Error> {
        Self::deserialize(&checkpoint.tree_state)
    }

    fn build_witness(
        &self,
        index: usize,
    ) -> Result<IncrementalWitness<MerkleHashOrchard, { ORCHARD_TREE_DEPTH }>, Error> {
        let mut working_tree = CommitmentTree::empty();
        let mut witness = None;
        for (i, node) in self.leaves.iter().enumerate() {
            working_tree
                .append(*node)
                .map_err(|_| TreeError::Internal("tree full".into()))?;
            if i == index {
                witness = Some(
                    IncrementalWitness::from_tree(working_tree.clone())
                        .expect("witness generation should succeed"),
                );
            } else if let Some(w) = witness.as_mut() {
                w.append(*node)
                    .map_err(|_| TreeError::Internal("unable to extend witness".into()))?;
            }
        }
        witness.ok_or_else(|| TreeError::MissingWitness(index as u64).into())
    }
}

pub fn deserialize_sapling_witness(
    encoded: &[u8],
) -> Result<IncrementalWitness<SaplingNode, { SAPLING_TREE_DEPTH }>, Error> {
    deserialize_witness_generic(encoded)
}

pub fn deserialize_orchard_witness(
    encoded: &[u8],
) -> Result<IncrementalWitness<MerkleHashOrchard, { ORCHARD_TREE_DEPTH }>, Error> {
    deserialize_witness_generic(encoded)
}

pub fn convert_path_to_sapling(
    path: incrementalmerkletree::MerklePath<SaplingNode, { SAPLING_TREE_DEPTH }>,
) -> Result<sapling::MerklePath, Error> {
    let elems = path
        .path_elems()
        .iter()
        .map(|node| node.as_inner())
        .collect::<Result<Vec<_>, _>>()?;
    sapling::MerklePath::from_parts(elems, path.position())
        .map_err(|_| Error::InvalidData("invalid sapling merkle path".into()))
}

pub fn convert_path_to_orchard(
    path: incrementalmerkletree::MerklePath<MerkleHashOrchard, { ORCHARD_TREE_DEPTH }>,
) -> Result<orchard::tree::MerklePath, Error> {
    Ok(path.into())
}

fn serialize_tree_generic<Node, const DEPTH: u8>(
    tree: &CommitmentTree<Node, DEPTH>,
) -> Result<Vec<u8>, Error>
where
    Node: HashSer + Hashable + Clone,
{
    let mut buf = Vec::new();
    write_commitment_tree::<Node, _, DEPTH>(tree, &mut buf)
        .map_err(|e| TreeError::Serialization(e.to_string()))?;
    Ok(buf)
}

fn deserialize_tree_generic<Node, const DEPTH: u8>(
    data: &[u8],
) -> Result<CommitmentTree<Node, DEPTH>, Error>
where
    Node: HashSer + Hashable + Clone,
{
    Ok(read_commitment_tree::<Node, _, DEPTH>(Cursor::new(data))
        .map_err(|e| TreeError::Serialization(e.to_string()))?)
}

#[derive(Serialize, Deserialize)]
struct PersistedTree {
    tree: Vec<u8>,
    leaves: Vec<[u8; 32]>,
}

fn serialize_witness_generic<Node, const DEPTH: u8>(
    witness: &IncrementalWitness<Node, DEPTH>,
) -> Result<Vec<u8>, Error>
where
    Node: HashSer + Hashable + Clone,
{
    let mut buf = Vec::new();
    write_incremental_witness::<Node, _, DEPTH>(witness, &mut buf)
        .map_err(|e| TreeError::Serialization(e.to_string()))?;
    Ok(buf)
}

fn deserialize_witness_generic<Node, const DEPTH: u8>(
    encoded: &[u8],
) -> Result<IncrementalWitness<Node, DEPTH>, Error>
where
    Node: HashSer + Hashable + Clone,
{
    read_incremental_witness::<Node, _, DEPTH>(Cursor::new(encoded))
        .map_err(|e| TreeError::Serialization(e.to_string()).into())
}

impl From<TreeError> for Error {
    fn from(err: TreeError) -> Self {
        Error::InvalidData(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_commitment(seed: u8) -> [u8; 32] {
        let mut bytes = [seed; 32];
        bytes[31] = seed;
        bytes
    }

    #[test]
    fn tree_initialization() {
        let tree = NoteCommitmentTree::new();
        assert_eq!(tree.size(), 0);
    }

    #[test]
    fn append_and_root() {
        let mut tree = NoteCommitmentTree::new();
        tree.append(sample_commitment(1)).unwrap();
        tree.append(sample_commitment(2)).unwrap();
        assert_eq!(tree.size(), 2);
        let root = tree.root().unwrap();
        assert_ne!(root, [0u8; 32]);
    }

    #[test]
    fn witness_generation() {
        let mut tree = NoteCommitmentTree::new();
        tree.append(sample_commitment(1)).unwrap();
        tree.append(sample_commitment(2)).unwrap();
        let witness_first = tree.witness_for_position(0).unwrap();
        let witness_second = tree.witness_for_position(1).unwrap();
        assert!(!witness_first.is_empty());
        assert_ne!(witness_first, witness_second);
        tree.verify_witness(1, &witness_second).unwrap();
    }

    #[test]
    fn serialization_round_trip() {
        let mut tree = NoteCommitmentTree::new();
        tree.append(sample_commitment(3)).unwrap();
        let encoded = tree.serialize().unwrap();
        let decoded = NoteCommitmentTree::deserialize(&encoded).unwrap();
        assert_eq!(tree.size(), decoded.size());
        assert_eq!(tree.root().unwrap(), decoded.root().unwrap());
    }

    #[test]
    fn verifies_tree_depth_constant() {
        assert_eq!(SAPLING_TREE_DEPTH, 32);
    }

    #[test]
    fn checkpoint_restore() {
        let mut tree = NoteCommitmentTree::new();
        tree.append(sample_commitment(4)).unwrap();
        let checkpoint = tree.checkpoint(Pool::Sapling, 100).unwrap();
        let restored = NoteCommitmentTree::restore(&checkpoint).unwrap();
        assert_eq!(restored.size(), tree.size());
        assert_eq!(restored.root().unwrap(), checkpoint.root);
    }

    #[test]
    fn orchard_tree_round_trip() {
        let mut tree = OrchardNoteCommitmentTree::new();
        let leaf = MerkleHashOrchard::empty_leaf().to_bytes();
        tree.append(leaf).unwrap();
        assert_eq!(tree.size(), 1);
        let root = tree.root().unwrap();
        assert_ne!(root, [0u8; 32]);
        let encoded = tree.serialize().unwrap();
        let decoded = OrchardNoteCommitmentTree::deserialize(&encoded).unwrap();
        assert_eq!(decoded.size(), 1);
        assert_eq!(decoded.root().unwrap(), root);
        let checkpoint = decoded.checkpoint(50).unwrap();
        assert_eq!(checkpoint.pool, Pool::Orchard);
        let restored = OrchardNoteCommitmentTree::restore(&checkpoint).unwrap();
        assert_eq!(restored.root().unwrap(), root);
    }
}
