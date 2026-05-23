//! Inline-friendly per-opcode helpers used by AOT shape handlers.
//!
//! Each helper assumes the caller has already pre-checked stack bounds
//! (via the shape handler's entry checks). They operate directly on the
//! stack memory through `top_pair_ptr_unchecked` and `shrink_unchecked`,
//! avoiding revm's popn_top/local-copy pattern and the per-opcode
//! function-call boundary.

use crate::{interpreter_types::StackTr, Interpreter, InterpreterTypes};
use primitives::U256;

/// Binary op `dst = src + dst`. Pops one (top), writes result to new top.
/// EVM ADD: pops a (top), b (top-1), pushes a+b (=b+a).
#[inline(always)]
pub unsafe fn add<W: InterpreterTypes>(interp: &mut Interpreter<W>) {
    let (dst, src) = interp.stack.top_pair_ptr_unchecked();
    // dst points at stack[len-2], src at stack[len-1].
    #[cfg(target_os = "zkvm")]
    {
        let d = dst as *mut u32;
        let s = src as *const u32;
        core::arch::asm!(
            "lw   t0, 0({d})",  "lw   t1, 0({s})",
            "add  t2, t0, t1",  "sltu t3, t2, t0",
            "sw   t2, 0({d})",
            "lw   t0, 4({d})",  "lw   t1, 4({s})",
            "add  t2, t0, t1",  "sltu t4, t2, t0",
            "add  t2, t2, t3",  "sltu t5, t2, t3",
            "or   t3, t4, t5",  "sw   t2, 4({d})",
            "lw   t0, 8({d})",  "lw   t1, 8({s})",
            "add  t2, t0, t1",  "sltu t4, t2, t0",
            "add  t2, t2, t3",  "sltu t5, t2, t3",
            "or   t3, t4, t5",  "sw   t2, 8({d})",
            "lw   t0, 12({d})", "lw   t1, 12({s})",
            "add  t2, t0, t1",  "sltu t4, t2, t0",
            "add  t2, t2, t3",  "sltu t5, t2, t3",
            "or   t3, t4, t5",  "sw   t2, 12({d})",
            "lw   t0, 16({d})", "lw   t1, 16({s})",
            "add  t2, t0, t1",  "sltu t4, t2, t0",
            "add  t2, t2, t3",  "sltu t5, t2, t3",
            "or   t3, t4, t5",  "sw   t2, 16({d})",
            "lw   t0, 20({d})", "lw   t1, 20({s})",
            "add  t2, t0, t1",  "sltu t4, t2, t0",
            "add  t2, t2, t3",  "sltu t5, t2, t3",
            "or   t3, t4, t5",  "sw   t2, 20({d})",
            "lw   t0, 24({d})", "lw   t1, 24({s})",
            "add  t2, t0, t1",  "sltu t4, t2, t0",
            "add  t2, t2, t3",  "sltu t5, t2, t3",
            "or   t3, t4, t5",  "sw   t2, 24({d})",
            "lw   t0, 28({d})", "lw   t1, 28({s})",
            "add  t2, t0, t1",
            "add  t2, t2, t3",
            "sw   t2, 28({d})",
            d = in(reg) d, s = in(reg) s,
            out("t0") _, out("t1") _, out("t2") _,
            out("t3") _, out("t4") _, out("t5") _,
            options(nostack, preserves_flags),
        );
    }
    #[cfg(not(target_os = "zkvm"))]
    {
        *dst = (*src).wrapping_add(*dst);
    }
    interp.stack.shrink_unchecked(1);
}

/// EVM SUB: pops a (top), b (top-1), pushes a-b. Result = src - dst.
#[inline(always)]
pub unsafe fn sub<W: InterpreterTypes>(interp: &mut Interpreter<W>) {
    let (dst, src) = interp.stack.top_pair_ptr_unchecked();
    *dst = (*src).wrapping_sub(*dst);
    interp.stack.shrink_unchecked(1);
}

/// EVM AND: pops a, b, pushes a & b.
#[inline(always)]
pub unsafe fn and<W: InterpreterTypes>(interp: &mut Interpreter<W>) {
    let (dst, src) = interp.stack.top_pair_ptr_unchecked();
    *dst = (*src) & (*dst);
    interp.stack.shrink_unchecked(1);
}

/// EVM OR: pops a, b, pushes a | b.
#[inline(always)]
pub unsafe fn or<W: InterpreterTypes>(interp: &mut Interpreter<W>) {
    let (dst, src) = interp.stack.top_pair_ptr_unchecked();
    *dst = (*src) | (*dst);
    interp.stack.shrink_unchecked(1);
}

/// EVM XOR: pops a, b, pushes a ^ b.
#[inline(always)]
pub unsafe fn xor<W: InterpreterTypes>(interp: &mut Interpreter<W>) {
    let (dst, src) = interp.stack.top_pair_ptr_unchecked();
    *dst = (*src) ^ (*dst);
    interp.stack.shrink_unchecked(1);
}

/// EVM EQ: pops a, b, pushes (a == b) as 0 or 1.
#[inline(always)]
pub unsafe fn eq<W: InterpreterTypes>(interp: &mut Interpreter<W>) {
    let (dst, src) = interp.stack.top_pair_ptr_unchecked();
    let r = if *src == *dst { U256::from(1u8) } else { U256::ZERO };
    *dst = r;
    interp.stack.shrink_unchecked(1);
}

/// EVM LT: pops a, b, pushes (a < b) as 0 or 1 (unsigned).
#[inline(always)]
pub unsafe fn lt<W: InterpreterTypes>(interp: &mut Interpreter<W>) {
    let (dst, src) = interp.stack.top_pair_ptr_unchecked();
    let r = if *src < *dst { U256::from(1u8) } else { U256::ZERO };
    *dst = r;
    interp.stack.shrink_unchecked(1);
}

/// EVM GT: pops a, b, pushes (a > b) as 0 or 1 (unsigned).
#[inline(always)]
pub unsafe fn gt<W: InterpreterTypes>(interp: &mut Interpreter<W>) {
    let (dst, src) = interp.stack.top_pair_ptr_unchecked();
    let r = if *src > *dst { U256::from(1u8) } else { U256::ZERO };
    *dst = r;
    interp.stack.shrink_unchecked(1);
}
