//! Hand-written type definitions for the AOT dispatch table. Kept separate
//! from `aot_table.rs` so the generator only touches the data file.

/// Kind of basic-block transpilation the AOT table dispatches to.
#[derive(Debug, Clone, Copy)]
pub enum AotKind {
    /// `DUP1 PUSH4 SEL EQ PUSH2 TGT JUMPI` — Solidity ABI selector dispatch.
    /// Compares stack top to `selector`; jumps to `target` if equal.
    SelectorDispatch { selector: u32, target: u16 },
    /// `JUMPDEST SWAP3 SWAP2 POP POP JUMP` — 4-arg function epilogue.
    /// Stack at entry: `[..., t, a, b, c, top]` (top is the return value).
    /// After: stack[len-4] = top, length -= 3, jump to original-index-3
    /// (the return PC).
    Epilogue,
}

#[derive(Debug, Clone, Copy)]
pub struct AotEntry {
    pub code_hash: [u8; 32],
    pub pc: u32,
    pub kind: AotKind,
}
