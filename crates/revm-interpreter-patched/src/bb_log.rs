//! Host-only basic-block fingerprint logger. Compiled to a no-op on zkvm
//! targets so the guest is unaffected. Used by tools/canonical-gas (or any
//! host-mode runner) to discover hot EVM basic-block shapes before
//! transpiling them.

#[cfg(not(target_os = "zkvm"))]
mod inner {
    use std::collections::HashMap;
    use std::sync::Mutex;
    use std::sync::OnceLock;

    /// JUMPDEST (0x5B) starts a new block.
    /// Terminators end the current one.
    const JUMPDEST: u8 = 0x5B;
    fn is_terminator(op: u8) -> bool {
        matches!(op, 0x00 /* STOP */ | 0x56 /* JUMP */ | 0x57 /* JUMPI */
                   | 0xF3 /* RETURN */ | 0xFD /* REVERT */
                   | 0xFE /* INVALID */ | 0xFF /* SELFDESTRUCT */)
    }

    struct State {
        enabled: bool,
        current: Vec<u8>,
        counts: HashMap<Vec<u8>, u64>,
        /// (code_hash, pc) -> (selector, target) for selector-dispatch matches
        /// found at runtime. Filled by `record_selector_match`. Drained for
        /// AOT-table generation by `drain_selector_matches`.
        selector_matches: HashMap<([u8; 32], u32), (u32, u16)>,
        /// (code_hash, pc) for epilogue (JUMPDEST SWAP3 SWAP2 POP POP JUMP) matches.
        epilogue_matches: std::collections::HashSet<([u8; 32], u32)>,
        /// Bytecodes seen during execution, keyed by code_hash. Captured at
        /// `ExtBytecode::new_with_optional_hash` time; used by the offline
        /// BB transpiler to enumerate every basic block in every touched
        /// contract.
        bytecodes: HashMap<[u8; 32], Vec<u8>>,
        /// Per-contract opcode-execution counts. Incremented by step() (host
        /// only) so the offline tool can pick the genuinely hot contract.
        op_counts: HashMap<[u8; 32], u64>,
    }

    fn state() -> &'static Mutex<State> {
        static S: OnceLock<Mutex<State>> = OnceLock::new();
        S.get_or_init(|| {
            Mutex::new(State {
                enabled: false,
                current: Vec::new(),
                counts: HashMap::new(),
                selector_matches: HashMap::new(),
                epilogue_matches: std::collections::HashSet::new(),
                bytecodes: HashMap::new(),
                op_counts: HashMap::new(),
            })
        })
    }

    pub fn enable() {
        let mut s = state().lock().unwrap();
        s.enabled = true;
        s.current.clear();
        s.counts.clear();
        s.selector_matches.clear();
        s.epilogue_matches.clear();
        s.bytecodes.clear();
    }

    pub fn record_bytecode(code_hash: [u8; 32], bytes: &[u8]) {
        let mut s = state().lock().unwrap();
        if !s.enabled {
            return;
        }
        s.bytecodes.entry(code_hash).or_insert_with(|| bytes.to_vec());
    }

    pub fn drain_bytecodes() -> Vec<([u8; 32], Vec<u8>)> {
        let mut s = state().lock().unwrap();
        let m = std::mem::take(&mut s.bytecodes);
        let mut v: Vec<_> = m.into_iter().collect();
        v.sort_by(|a, b| a.0.cmp(&b.0));
        v
    }

    pub fn record_op_count(code_hash: [u8; 32]) {
        let mut s = state().lock().unwrap();
        if !s.enabled {
            return;
        }
        *s.op_counts.entry(code_hash).or_insert(0) += 1;
    }

    pub fn drain_op_counts() -> Vec<([u8; 32], u64)> {
        let mut s = state().lock().unwrap();
        let m = std::mem::take(&mut s.op_counts);
        let mut v: Vec<_> = m.into_iter().collect();
        v.sort_by_key(|(_, c)| std::cmp::Reverse(*c));
        v
    }

    pub fn record_selector_match(code_hash: [u8; 32], pc: u32, sel: u32, tgt: u16) {
        let mut s = state().lock().unwrap();
        if !s.enabled {
            return;
        }
        s.selector_matches.insert((code_hash, pc), (sel, tgt));
    }

    /// Returns the deduped set of (code_hash, pc, sel, tgt) matches seen.
    /// Sorted lexicographically by (code_hash, pc) for stable output.
    pub fn drain_selector_matches() -> Vec<([u8; 32], u32, u32, u16)> {
        let mut s = state().lock().unwrap();
        let m = std::mem::take(&mut s.selector_matches);
        let mut v: Vec<_> = m.into_iter().map(|((h, p), (s, t))| (h, p, s, t)).collect();
        v.sort();
        v
    }

    pub fn record_epilogue_match(code_hash: [u8; 32], pc: u32) {
        let mut s = state().lock().unwrap();
        if !s.enabled {
            return;
        }
        s.epilogue_matches.insert((code_hash, pc));
    }

    pub fn drain_epilogue_matches() -> Vec<([u8; 32], u32)> {
        let mut s = state().lock().unwrap();
        let m = std::mem::take(&mut s.epilogue_matches);
        let mut v: Vec<_> = m.into_iter().collect();
        v.sort();
        v
    }

    pub fn record(opcode: u8) {
        let mut s = state().lock().unwrap();
        if !s.enabled {
            return;
        }
        if opcode == JUMPDEST && !s.current.is_empty() {
            let block = std::mem::take(&mut s.current);
            *s.counts.entry(block).or_insert(0) += 1;
        }
        s.current.push(opcode);
        if is_terminator(opcode) {
            let block = std::mem::take(&mut s.current);
            *s.counts.entry(block).or_insert(0) += 1;
        }
    }

    /// Drain. Returns `(shape_bytes, count)` sorted by `count * shape.len()` descending.
    pub fn drain() -> Vec<(Vec<u8>, u64)> {
        let mut s = state().lock().unwrap();
        s.enabled = false;
        s.current.clear();
        let counts = std::mem::take(&mut s.counts);
        let mut v: Vec<_> = counts.into_iter().collect();
        v.sort_by_key(|(shape, count)| std::cmp::Reverse(*count * shape.len() as u64));
        v
    }
}

#[cfg(not(target_os = "zkvm"))]
pub use inner::{
    drain, drain_bytecodes, drain_epilogue_matches, drain_op_counts, drain_selector_matches,
    enable, record, record_bytecode, record_epilogue_match, record_op_count,
    record_selector_match,
};

#[cfg(target_os = "zkvm")]
#[inline(always)]
pub fn record(_opcode: u8) {}

#[cfg(target_os = "zkvm")]
#[inline(always)]
pub fn record_selector_match(_h: [u8; 32], _p: u32, _s: u32, _t: u16) {}

#[cfg(target_os = "zkvm")]
#[inline(always)]
pub fn record_epilogue_match(_h: [u8; 32], _p: u32) {}

#[cfg(target_os = "zkvm")]
#[inline(always)]
pub fn record_bytecode(_h: [u8; 32], _b: &[u8]) {}

#[cfg(target_os = "zkvm")]
#[inline(always)]
pub fn record_op_count(_h: [u8; 32]) {}
