use super::{Immediates, Jumps, LegacyBytecode};
use crate::{interpreter_types::LoopControl, InterpreterAction};
use bytecode::{utils::read_u16, Bytecode};
use core::ops::Deref;
use primitives::B256;

/// Walks [`crate::aot_table::AOT_TABLE`] (sorted by `(code_hash, pc)`)
/// for entries matching `hash` and writes `1 + idx` into `table[pc]` for each.
#[cfg(feature = "evm-aot")]
fn fill_aot_table(hash: &[u8; 32], table: &mut [u16]) {
    use crate::aot_table::AOT_TABLE;
    let lower = AOT_TABLE.partition_point(|e| &e.code_hash < hash);
    let mut i = lower;
    while i < AOT_TABLE.len() && &AOT_TABLE[i].code_hash == hash {
        let pc = AOT_TABLE[i].pc as usize;
        if pc < table.len() {
            table[pc] = (i + 1) as u16;
        }
        i += 1;
    }
}

#[cfg(feature = "evm-bb-aot")]
fn build_bb_walker_dispatch(hash: &[u8; 32], len: usize) -> std::sync::Arc<[u32]> {
    use crate::bb_walker_table::BB_WALKER_TABLE;
    let mut table: std::vec::Vec<u32> = std::vec![0u32; len];
    let lower = BB_WALKER_TABLE.partition_point(|e| &e.code_hash < hash);
    let mut i = lower;
    while i < BB_WALKER_TABLE.len() && &BB_WALKER_TABLE[i].code_hash == hash {
        let pc = BB_WALKER_TABLE[i].pc as usize;
        if pc < table.len() {
            table[pc] = (i + 1) as u32;
        }
        i += 1;
    }
    std::sync::Arc::from(table.into_boxed_slice())
}

/// Get-or-insert into a process-wide `(code_hash) -> (Arc<[u32]>, aot_present)`
/// cache. Each unique contract is analyzed at most once.
#[cfg(feature = "evm-bb-aot")]
fn cached_bb_walker_dispatch(
    hash: &[u8; 32],
    len: usize,
) -> (std::sync::Arc<[u32]>, bool) {
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};
    static CACHE: OnceLock<Mutex<HashMap<[u8; 32], (std::sync::Arc<[u32]>, bool)>>> =
        OnceLock::new();
    let m = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let mut g = m.lock().unwrap();
    if let Some(v) = g.get(hash) {
        return v.clone();
    }
    use crate::bb_walker_table::BB_WALKER_TABLE;
    let lower = BB_WALKER_TABLE.partition_point(|e| &e.code_hash < hash);
    let present = lower < BB_WALKER_TABLE.len() && &BB_WALKER_TABLE[lower].code_hash == hash;
    let arc = build_bb_walker_dispatch(hash, len);
    let v = (arc, present);
    g.insert(*hash, v.clone());
    v
}

#[cfg(feature = "evm-bb-aot")]
fn empty_dispatch_table() -> std::sync::Arc<[u32]> {
    use std::sync::OnceLock;
    static EMPTY: OnceLock<std::sync::Arc<[u32]>> = OnceLock::new();
    EMPTY.get_or_init(|| std::sync::Arc::from(std::vec::Vec::new().into_boxed_slice())).clone()
}

#[cfg(feature = "serde")]
mod serde;

/// Extended bytecode structure that wraps base bytecode with additional execution metadata.
#[derive(Debug)]
pub struct ExtBytecode {
    /// The current instruction pointer.
    instruction_pointer: *const u8,
    /// Whether the execution should continue.
    continue_execution: bool,
    /// Bytecode Keccak-256 hash.
    /// This is `None` if it hasn't been calculated yet.
    /// Since it's not necessary for execution, it's not calculated by default.
    bytecode_hash: Option<B256>,
    /// Per-pc dispatch table for the AOT transpiled basic blocks.
    /// Indexed by pc: `0` = no entry; `1 + idx` = index into
    /// [`crate::aot_table::AOT_TABLE`]. Populated when a hash is available.
    #[cfg(feature = "evm-aot")]
    aot_table: std::boxed::Box<[u16]>,
    /// Per-pc dispatch index for the generic-BB walker. `0` = no entry;
    /// `1 + idx` = index into [`crate::bb_walker_table::BB_WALKER_TABLE`].
    /// `u32` because the table can exceed 65K entries. Shared across call
    /// frames of the same contract via a per-`code_hash` global cache.
    #[cfg(feature = "evm-bb-aot")]
    bb_walker_dispatch: std::sync::Arc<[u32]>,
    /// True iff this contract has at least one AOT BB entry. The JUMPDEST
    /// and JUMPI hooks early-return when this is false, paying only a
    /// single-byte-load + branch instead of the full per-pc table lookup.
    #[cfg(feature = "evm-bb-aot")]
    aot_present: bool,
    /// Set when the next [`step`](crate::Interpreter::step) is known to be
    /// at a basic-block boundary (frame entry, JUMPI fall-through). step()
    /// only consults the AOT dispatch table when this is set or the
    /// current opcode is JUMPDEST.
    #[cfg(feature = "evm-bb-aot")]
    pending_bb_check: bool,
    /// Actions that the EVM should do. It contains return value of the Interpreter or inputs for `CALL` or `CREATE` instructions.
    /// For `RETURN` or `REVERT` instructions it contains the result of the instruction.
    pub action: Option<InterpreterAction>,
    /// The base bytecode.
    base: Bytecode,
}

impl Deref for ExtBytecode {
    type Target = Bytecode;

    fn deref(&self) -> &Self::Target {
        &self.base
    }
}

impl Default for ExtBytecode {
    #[inline]
    fn default() -> Self {
        Self::new(Bytecode::default())
    }
}

impl ExtBytecode {
    /// Create new extended bytecode and set the instruction pointer to the start of the bytecode.
    ///
    /// The bytecode hash will not be calculated.
    #[inline]
    pub fn new(base: Bytecode) -> Self {
        Self::new_with_optional_hash(base, None)
    }

    /// Creates new `ExtBytecode` with the given hash.
    #[inline]
    pub fn new_with_hash(base: Bytecode, hash: B256) -> Self {
        Self::new_with_optional_hash(base, Some(hash))
    }

    /// Creates new `ExtBytecode` with the given hash.
    #[inline]
    pub fn new_with_optional_hash(base: Bytecode, hash: Option<B256>) -> Self {
        let instruction_pointer = base.bytecode_ptr();
        // Host-only: capture (code_hash, bytecode) so the offline BB
        // transpiler can enumerate every basic block.
        #[cfg(not(target_os = "zkvm"))]
        if let Some(h) = hash {
            crate::bb_log::record_bytecode(h.0, base.bytes_ref());
        }
        #[cfg(feature = "evm-aot")]
        let aot_table = {
            let len = base.bytes_ref().len();
            let mut table: std::boxed::Box<[u16]> = std::vec![0u16; len].into_boxed_slice();
            if let Some(h) = hash {
                fill_aot_table(&h.0, &mut table);
            }
            table
        };
        #[cfg(feature = "evm-bb-aot")]
        let (bb_walker_dispatch, aot_present) = {
            let len = base.bytes_ref().len();
            if let Some(h) = hash {
                cached_bb_walker_dispatch(&h.0, len)
            } else {
                // No hash: can't cache. Fall back to an empty table allocation
                // of the right size so the per-pc `get_unchecked` stays valid.
                (
                    std::sync::Arc::from(std::vec![0u32; len].into_boxed_slice()),
                    false,
                )
            }
        };
        Self {
            base,
            instruction_pointer,
            bytecode_hash: hash,
            #[cfg(feature = "evm-aot")]
            aot_table,
            #[cfg(feature = "evm-bb-aot")]
            bb_walker_dispatch,
            #[cfg(feature = "evm-bb-aot")]
            aot_present,
            #[cfg(feature = "evm-bb-aot")]
            pending_bb_check: true,
            action: None,
            continue_execution: true,
        }
    }

    /// Re-calculates the bytecode hash.
    ///
    /// Prefer [`get_or_calculate_hash`](Self::get_or_calculate_hash) if you just need to get the hash.
    #[inline]
    pub fn calculate_hash(&mut self) -> B256 {
        let hash = self.base.hash_slow();
        self.bytecode_hash = Some(hash);
        hash
    }

    /// Returns the bytecode hash.
    #[inline]
    pub fn hash(&mut self) -> Option<B256> {
        self.bytecode_hash
    }

    /// Returns the bytecode hash or calculates it if it is not set.
    #[inline]
    pub fn get_or_calculate_hash(&mut self) -> B256 {
        *self.bytecode_hash.get_or_insert_with(
            #[cold]
            || self.base.hash_slow(),
        )
    }
}

impl LoopControl for ExtBytecode {
    #[inline]
    fn is_not_end(&self) -> bool {
        self.continue_execution
    }

    #[inline]
    fn reset_action(&mut self) {
        self.continue_execution = true;
    }

    #[inline]
    fn set_action(&mut self, action: InterpreterAction) {
        debug_assert_eq!(
            !self.continue_execution,
            self.action.is_some(),
            "has_set_action out of sync"
        );
        debug_assert!(
            self.continue_execution,
            "action already set;\nold: {:#?}\nnew: {:#?}",
            self.action, action,
        );
        self.continue_execution = false;
        self.action = Some(action);
    }

    #[inline]
    fn action(&mut self) -> &mut Option<InterpreterAction> {
        &mut self.action
    }
}

impl Jumps for ExtBytecode {
    #[inline]
    fn relative_jump(&mut self, offset: isize) {
        self.instruction_pointer = unsafe { self.instruction_pointer.offset(offset) };
    }

    #[inline]
    fn absolute_jump(&mut self, offset: usize) {
        self.instruction_pointer = unsafe { self.base.bytes_ref().as_ptr().add(offset) };
    }

    #[inline]
    fn is_valid_legacy_jump(&mut self, offset: usize) -> bool {
        self.base
            .legacy_jump_table()
            .expect("Panic if not legacy")
            .is_valid(offset)
    }

    #[inline]
    fn opcode(&self) -> u8 {
        // SAFETY: `instruction_pointer` always point to bytecode.
        unsafe { *self.instruction_pointer }
    }

    #[inline]
    fn bytecode_hash_bytes(&mut self) -> [u8; 32] {
        let h = *self.bytecode_hash.get_or_insert_with(
            #[cold]
            || self.base.hash_slow(),
        );
        h.0
    }

    #[inline(always)]
    fn aot_table_idx(&mut self) -> u16 {
        #[cfg(feature = "evm-aot")]
        {
            let pc = unsafe {
                self.instruction_pointer
                    .offset_from_unsigned(self.base.bytes_ref().as_ptr())
            };
            // SAFETY: instruction_pointer is always within bytes; table
            // has bytes.len() entries (zero-padded for non-matching pcs).
            unsafe { *self.aot_table.get_unchecked(pc) }
        }
        #[cfg(not(feature = "evm-aot"))]
        {
            0
        }
    }

    #[inline(always)]
    fn bb_walker_idx(&mut self) -> u32 {
        #[cfg(feature = "evm-bb-aot")]
        {
            let pc = unsafe {
                self.instruction_pointer
                    .offset_from_unsigned(self.base.bytes_ref().as_ptr())
            };
            unsafe { *self.bb_walker_dispatch.get_unchecked(pc) }
        }
        #[cfg(not(feature = "evm-bb-aot"))]
        {
            0
        }
    }

    #[inline(always)]
    fn take_pending_bb_check(&mut self) -> bool {
        #[cfg(feature = "evm-bb-aot")]
        {
            let v = self.pending_bb_check;
            self.pending_bb_check = false;
            v
        }
        #[cfg(not(feature = "evm-bb-aot"))]
        {
            false
        }
    }

    #[inline(always)]
    fn set_pending_bb_check(&mut self) {
        #[cfg(feature = "evm-bb-aot")]
        {
            self.pending_bb_check = true;
        }
    }

    #[inline(always)]
    fn aot_present(&self) -> bool {
        #[cfg(feature = "evm-bb-aot")]
        {
            self.aot_present
        }
        #[cfg(not(feature = "evm-bb-aot"))]
        {
            false
        }
    }

    #[inline]
    fn pc(&self) -> usize {
        // SAFETY: `instruction_pointer` should be at an offset from the start of the bytes.
        // In practice this is always true unless a caller modifies the `instruction_pointer` field manually.
        unsafe {
            self.instruction_pointer
                .offset_from_unsigned(self.base.bytes_ref().as_ptr())
        }
    }
}

impl Immediates for ExtBytecode {
    #[inline]
    fn read_u16(&self) -> u16 {
        unsafe { read_u16(self.instruction_pointer) }
    }

    #[inline]
    fn read_u8(&self) -> u8 {
        unsafe { *self.instruction_pointer }
    }

    #[inline]
    fn read_slice(&self, len: usize) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self.instruction_pointer, len) }
    }

    #[inline]
    fn read_offset_u16(&self, offset: isize) -> u16 {
        unsafe {
            read_u16(
                self.instruction_pointer
                    // Offset for max_index that is one byte
                    .offset(offset),
            )
        }
    }
}

impl LegacyBytecode for ExtBytecode {
    fn bytecode_len(&self) -> usize {
        self.base.len()
    }

    fn bytecode_slice(&self) -> &[u8] {
        self.base.original_byte_slice()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use primitives::Bytes;

    #[test]
    fn test_with_hash_constructor() {
        let bytecode = Bytecode::new_raw(Bytes::from(&[0x60, 0x00][..]));
        let hash = bytecode.hash_slow();
        let ext_bytecode = ExtBytecode::new_with_hash(bytecode.clone(), hash);
        assert_eq!(ext_bytecode.bytecode_hash, Some(hash));
    }
}
