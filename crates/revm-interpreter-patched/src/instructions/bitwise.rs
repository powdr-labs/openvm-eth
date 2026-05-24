use super::i256::i256_cmp;
use crate::{
    interpreter_types::{InterpreterTypes, RuntimeFlag, StackTr},
    InstructionContext,
};
use core::cmp::Ordering;
use primitives::U256;

/// Implements the LT instruction - less than comparison.
pub fn lt<WIRE: InterpreterTypes, H: ?Sized>(context: InstructionContext<'_, H, WIRE>) {
    #[cfg(target_os = "zkvm")]
    {
        if context.interpreter.stack.len() < 2 {
            context.interpreter.halt_underflow();
            return;
        }
        unsafe {
            let (dst, src) = context.interpreter.stack.top_pair_ptr_unchecked();
            let d = dst as *mut u32;
            let s = src as *const u32;
            // 8-limb unsigned sub-borrow chain (s - d). Final borrow = (s < d).
            core::arch::asm!(
                "lw   {aw},  0({s})",
                "lw   {bw},  0({d})",
                "sltu {c}, {aw}, {bw}",
                "lw   {aw},  4({s})", "lw {bw},  4({d})",
                "sub  {r}, {aw}, {bw}", "sltu {t}, {aw}, {bw}",
                "sltu {u}, {r}, {c}", "or {c}, {t}, {u}",
                "lw   {aw},  8({s})", "lw {bw},  8({d})",
                "sub  {r}, {aw}, {bw}", "sltu {t}, {aw}, {bw}",
                "sltu {u}, {r}, {c}", "or {c}, {t}, {u}",
                "lw   {aw}, 12({s})", "lw {bw}, 12({d})",
                "sub  {r}, {aw}, {bw}", "sltu {t}, {aw}, {bw}",
                "sltu {u}, {r}, {c}", "or {c}, {t}, {u}",
                "lw   {aw}, 16({s})", "lw {bw}, 16({d})",
                "sub  {r}, {aw}, {bw}", "sltu {t}, {aw}, {bw}",
                "sltu {u}, {r}, {c}", "or {c}, {t}, {u}",
                "lw   {aw}, 20({s})", "lw {bw}, 20({d})",
                "sub  {r}, {aw}, {bw}", "sltu {t}, {aw}, {bw}",
                "sltu {u}, {r}, {c}", "or {c}, {t}, {u}",
                "lw   {aw}, 24({s})", "lw {bw}, 24({d})",
                "sub  {r}, {aw}, {bw}", "sltu {t}, {aw}, {bw}",
                "sltu {u}, {r}, {c}", "or {c}, {t}, {u}",
                "lw   {aw}, 28({s})", "lw {bw}, 28({d})",
                "sub  {r}, {aw}, {bw}", "sltu {t}, {aw}, {bw}",
                "sltu {u}, {r}, {c}", "or {c}, {t}, {u}",
                "sw   {c},  0({d})",
                "sw   zero,  4({d})", "sw zero,  8({d})", "sw zero, 12({d})",
                "sw   zero, 16({d})", "sw zero, 20({d})", "sw zero, 24({d})",
                "sw   zero, 28({d})",
                d = in(reg) d,
                s = in(reg) s,
                aw = out(reg) _,
                bw = out(reg) _,
                r = out(reg) _,
                c = out(reg) _,
                t = out(reg) _,
                u = out(reg) _,
                options(nostack, preserves_flags),
            );
            context.interpreter.stack.shrink_unchecked(1);
        }
    }
    #[cfg(not(target_os = "zkvm"))]
    {
        popn_top!([op1], op2, context.interpreter);
        *op2 = U256::from(op1 < *op2);
    }
}

/// Implements the GT instruction - greater than comparison.
pub fn gt<WIRE: InterpreterTypes, H: ?Sized>(context: InstructionContext<'_, H, WIRE>) {
    #[cfg(target_os = "zkvm")]
    {
        if context.interpreter.stack.len() < 2 {
            context.interpreter.halt_underflow();
            return;
        }
        unsafe {
            let (dst, src) = context.interpreter.stack.top_pair_ptr_unchecked();
            let d = dst as *mut u32;
            let s = src as *const u32;
            // GT(s, d) = LT(d, s). Subtract d - s, final borrow = result.
            core::arch::asm!(
                "lw   {aw},  0({d})",
                "lw   {bw},  0({s})",
                "sltu {c}, {aw}, {bw}",
                "lw   {aw},  4({d})", "lw {bw},  4({s})",
                "sub  {r}, {aw}, {bw}", "sltu {t}, {aw}, {bw}",
                "sltu {u}, {r}, {c}", "or {c}, {t}, {u}",
                "lw   {aw},  8({d})", "lw {bw},  8({s})",
                "sub  {r}, {aw}, {bw}", "sltu {t}, {aw}, {bw}",
                "sltu {u}, {r}, {c}", "or {c}, {t}, {u}",
                "lw   {aw}, 12({d})", "lw {bw}, 12({s})",
                "sub  {r}, {aw}, {bw}", "sltu {t}, {aw}, {bw}",
                "sltu {u}, {r}, {c}", "or {c}, {t}, {u}",
                "lw   {aw}, 16({d})", "lw {bw}, 16({s})",
                "sub  {r}, {aw}, {bw}", "sltu {t}, {aw}, {bw}",
                "sltu {u}, {r}, {c}", "or {c}, {t}, {u}",
                "lw   {aw}, 20({d})", "lw {bw}, 20({s})",
                "sub  {r}, {aw}, {bw}", "sltu {t}, {aw}, {bw}",
                "sltu {u}, {r}, {c}", "or {c}, {t}, {u}",
                "lw   {aw}, 24({d})", "lw {bw}, 24({s})",
                "sub  {r}, {aw}, {bw}", "sltu {t}, {aw}, {bw}",
                "sltu {u}, {r}, {c}", "or {c}, {t}, {u}",
                "lw   {aw}, 28({d})", "lw {bw}, 28({s})",
                "sub  {r}, {aw}, {bw}", "sltu {t}, {aw}, {bw}",
                "sltu {u}, {r}, {c}", "or {c}, {t}, {u}",
                "sw   {c},  0({d})",
                "sw   zero,  4({d})", "sw zero,  8({d})", "sw zero, 12({d})",
                "sw   zero, 16({d})", "sw zero, 20({d})", "sw zero, 24({d})",
                "sw   zero, 28({d})",
                d = in(reg) d,
                s = in(reg) s,
                aw = out(reg) _,
                bw = out(reg) _,
                r = out(reg) _,
                c = out(reg) _,
                t = out(reg) _,
                u = out(reg) _,
                options(nostack, preserves_flags),
            );
            context.interpreter.stack.shrink_unchecked(1);
        }
    }
    #[cfg(not(target_os = "zkvm"))]
    {
        popn_top!([op1], op2, context.interpreter);
        *op2 = U256::from(op1 > *op2);
    }
}

/// Implements the CLZ instruction - count leading zeros.
pub fn clz<WIRE: InterpreterTypes, H: ?Sized>(context: InstructionContext<'_, H, WIRE>) {
    check!(context.interpreter, OSAKA);
    popn_top!([], op1, context.interpreter);
    let leading_zeros = op1.leading_zeros();
    *op1 = U256::from(leading_zeros);
}

/// Implements the SLT instruction.
///
/// Signed less than comparison of two values from stack.
pub fn slt<WIRE: InterpreterTypes, H: ?Sized>(context: InstructionContext<'_, H, WIRE>) {
    #[cfg(target_os = "zkvm")]
    {
        if context.interpreter.stack.len() < 2 {
            context.interpreter.halt_underflow();
            return;
        }
        unsafe {
            let (dst, src) = context.interpreter.stack.top_pair_ptr_unchecked();
            let d = dst as *mut u32;
            let s = src as *const u32;
            let sign_mask: u32 = 0x8000_0000;
            // Signed (s < d): XOR the MSB limb (28..31) of both with sign bit,
            // then unsigned compare. Final borrow chain gives result.
            core::arch::asm!(
                "lw   {aw},  0({s})",
                "lw   {bw},  0({d})",
                "sltu {c}, {aw}, {bw}",
                "lw   {aw},  4({s})", "lw {bw},  4({d})",
                "sub  {r}, {aw}, {bw}", "sltu {t}, {aw}, {bw}",
                "sltu {u}, {r}, {c}", "or {c}, {t}, {u}",
                "lw   {aw},  8({s})", "lw {bw},  8({d})",
                "sub  {r}, {aw}, {bw}", "sltu {t}, {aw}, {bw}",
                "sltu {u}, {r}, {c}", "or {c}, {t}, {u}",
                "lw   {aw}, 12({s})", "lw {bw}, 12({d})",
                "sub  {r}, {aw}, {bw}", "sltu {t}, {aw}, {bw}",
                "sltu {u}, {r}, {c}", "or {c}, {t}, {u}",
                "lw   {aw}, 16({s})", "lw {bw}, 16({d})",
                "sub  {r}, {aw}, {bw}", "sltu {t}, {aw}, {bw}",
                "sltu {u}, {r}, {c}", "or {c}, {t}, {u}",
                "lw   {aw}, 20({s})", "lw {bw}, 20({d})",
                "sub  {r}, {aw}, {bw}", "sltu {t}, {aw}, {bw}",
                "sltu {u}, {r}, {c}", "or {c}, {t}, {u}",
                "lw   {aw}, 24({s})", "lw {bw}, 24({d})",
                "sub  {r}, {aw}, {bw}", "sltu {t}, {aw}, {bw}",
                "sltu {u}, {r}, {c}", "or {c}, {t}, {u}",
                "lw   {aw}, 28({s})", "lw {bw}, 28({d})",
                "xor  {aw}, {aw}, {m}", "xor {bw}, {bw}, {m}",
                "sub  {r}, {aw}, {bw}", "sltu {t}, {aw}, {bw}",
                "sltu {u}, {r}, {c}", "or {c}, {t}, {u}",
                "sw   {c},  0({d})",
                "sw   zero,  4({d})", "sw zero,  8({d})", "sw zero, 12({d})",
                "sw   zero, 16({d})", "sw zero, 20({d})", "sw zero, 24({d})",
                "sw   zero, 28({d})",
                d = in(reg) d,
                s = in(reg) s,
                m = in(reg) sign_mask,
                aw = out(reg) _,
                bw = out(reg) _,
                r = out(reg) _,
                c = out(reg) _,
                t = out(reg) _,
                u = out(reg) _,
                options(nostack, preserves_flags),
            );
            context.interpreter.stack.shrink_unchecked(1);
        }
    }
    #[cfg(not(target_os = "zkvm"))]
    {
        popn_top!([op1], op2, context.interpreter);
        *op2 = U256::from(i256_cmp(&op1, op2) == Ordering::Less);
    }
}

/// Implements the SGT instruction.
///
/// Signed greater than comparison of two values from stack.
pub fn sgt<WIRE: InterpreterTypes, H: ?Sized>(context: InstructionContext<'_, H, WIRE>) {
    #[cfg(target_os = "zkvm")]
    {
        if context.interpreter.stack.len() < 2 {
            context.interpreter.halt_underflow();
            return;
        }
        unsafe {
            let (dst, src) = context.interpreter.stack.top_pair_ptr_unchecked();
            let d = dst as *mut u32;
            let s = src as *const u32;
            let sign_mask: u32 = 0x8000_0000;
            // Signed (s > d) = signed (d < s). Subtract d - s with MSB flipped.
            core::arch::asm!(
                "lw   {aw},  0({d})",
                "lw   {bw},  0({s})",
                "sltu {c}, {aw}, {bw}",
                "lw   {aw},  4({d})", "lw {bw},  4({s})",
                "sub  {r}, {aw}, {bw}", "sltu {t}, {aw}, {bw}",
                "sltu {u}, {r}, {c}", "or {c}, {t}, {u}",
                "lw   {aw},  8({d})", "lw {bw},  8({s})",
                "sub  {r}, {aw}, {bw}", "sltu {t}, {aw}, {bw}",
                "sltu {u}, {r}, {c}", "or {c}, {t}, {u}",
                "lw   {aw}, 12({d})", "lw {bw}, 12({s})",
                "sub  {r}, {aw}, {bw}", "sltu {t}, {aw}, {bw}",
                "sltu {u}, {r}, {c}", "or {c}, {t}, {u}",
                "lw   {aw}, 16({d})", "lw {bw}, 16({s})",
                "sub  {r}, {aw}, {bw}", "sltu {t}, {aw}, {bw}",
                "sltu {u}, {r}, {c}", "or {c}, {t}, {u}",
                "lw   {aw}, 20({d})", "lw {bw}, 20({s})",
                "sub  {r}, {aw}, {bw}", "sltu {t}, {aw}, {bw}",
                "sltu {u}, {r}, {c}", "or {c}, {t}, {u}",
                "lw   {aw}, 24({d})", "lw {bw}, 24({s})",
                "sub  {r}, {aw}, {bw}", "sltu {t}, {aw}, {bw}",
                "sltu {u}, {r}, {c}", "or {c}, {t}, {u}",
                "lw   {aw}, 28({d})", "lw {bw}, 28({s})",
                "xor  {aw}, {aw}, {m}", "xor {bw}, {bw}, {m}",
                "sub  {r}, {aw}, {bw}", "sltu {t}, {aw}, {bw}",
                "sltu {u}, {r}, {c}", "or {c}, {t}, {u}",
                "sw   {c},  0({d})",
                "sw   zero,  4({d})", "sw zero,  8({d})", "sw zero, 12({d})",
                "sw   zero, 16({d})", "sw zero, 20({d})", "sw zero, 24({d})",
                "sw   zero, 28({d})",
                d = in(reg) d,
                s = in(reg) s,
                m = in(reg) sign_mask,
                aw = out(reg) _,
                bw = out(reg) _,
                r = out(reg) _,
                c = out(reg) _,
                t = out(reg) _,
                u = out(reg) _,
                options(nostack, preserves_flags),
            );
            context.interpreter.stack.shrink_unchecked(1);
        }
    }
    #[cfg(not(target_os = "zkvm"))]
    {
        popn_top!([op1], op2, context.interpreter);
        *op2 = U256::from(i256_cmp(&op1, op2) == Ordering::Greater);
    }
}

/// Implements the EQ instruction.
///
/// Equality comparison of two values from stack.
pub fn eq<WIRE: InterpreterTypes, H: ?Sized>(context: InstructionContext<'_, H, WIRE>) {
    #[cfg(target_os = "zkvm")]
    {
        if context.interpreter.stack.len() < 2 {
            context.interpreter.halt_underflow();
            return;
        }
        unsafe {
            let (dst, src) = context.interpreter.stack.top_pair_ptr_unchecked();
            let d = dst as *mut u32;
            let s = src as *const u32;
            core::arch::asm!(
                "lw   {a},  0({d})",
                "lw   {b},  0({s})",
                "xor  {acc}, {a}, {b}",
                "lw   {a},  4({d})",
                "lw   {b},  4({s})",
                "xor  {a}, {a}, {b}",
                "or   {acc}, {acc}, {a}",
                "lw   {a},  8({d})",
                "lw   {b},  8({s})",
                "xor  {a}, {a}, {b}",
                "or   {acc}, {acc}, {a}",
                "lw   {a}, 12({d})",
                "lw   {b}, 12({s})",
                "xor  {a}, {a}, {b}",
                "or   {acc}, {acc}, {a}",
                "lw   {a}, 16({d})",
                "lw   {b}, 16({s})",
                "xor  {a}, {a}, {b}",
                "or   {acc}, {acc}, {a}",
                "lw   {a}, 20({d})",
                "lw   {b}, 20({s})",
                "xor  {a}, {a}, {b}",
                "or   {acc}, {acc}, {a}",
                "lw   {a}, 24({d})",
                "lw   {b}, 24({s})",
                "xor  {a}, {a}, {b}",
                "or   {acc}, {acc}, {a}",
                "lw   {a}, 28({d})",
                "lw   {b}, 28({s})",
                "xor  {a}, {a}, {b}",
                "or   {acc}, {acc}, {a}",
                // acc == 0 iff all limbs equal
                "sltiu {acc}, {acc}, 1",
                "sw   {acc},  0({d})",
                "sw   zero,  4({d})",
                "sw   zero,  8({d})",
                "sw   zero, 12({d})",
                "sw   zero, 16({d})",
                "sw   zero, 20({d})",
                "sw   zero, 24({d})",
                "sw   zero, 28({d})",
                d = in(reg) d,
                s = in(reg) s,
                a = out(reg) _,
                b = out(reg) _,
                acc = out(reg) _,
                options(nostack, preserves_flags),
            );
            context.interpreter.stack.shrink_unchecked(1);
        }
    }
    #[cfg(not(target_os = "zkvm"))]
    {
        popn_top!([op1], op2, context.interpreter);
        *op2 = U256::from(op1 == *op2);
    }
}

/// Implements the ISZERO instruction.
///
/// Checks if the top stack value is zero.
pub fn iszero<WIRE: InterpreterTypes, H: ?Sized>(context: InstructionContext<'_, H, WIRE>) {
    #[cfg(target_os = "zkvm")]
    {
        if context.interpreter.stack.len() < 1 {
            context.interpreter.halt_underflow();
            return;
        }
        unsafe {
            let top = context.interpreter.stack.top_ptr_unchecked() as *mut u32;
            core::arch::asm!(
                "lw   {acc},  0({d})",
                "lw   {a},   4({d})",
                "or   {acc}, {acc}, {a}",
                "lw   {a},   8({d})",
                "or   {acc}, {acc}, {a}",
                "lw   {a},  12({d})",
                "or   {acc}, {acc}, {a}",
                "lw   {a},  16({d})",
                "or   {acc}, {acc}, {a}",
                "lw   {a},  20({d})",
                "or   {acc}, {acc}, {a}",
                "lw   {a},  24({d})",
                "or   {acc}, {acc}, {a}",
                "lw   {a},  28({d})",
                "or   {acc}, {acc}, {a}",
                "sltiu {acc}, {acc}, 1",
                "sw   {acc},  0({d})",
                "sw   zero,  4({d})",
                "sw   zero,  8({d})",
                "sw   zero, 12({d})",
                "sw   zero, 16({d})",
                "sw   zero, 20({d})",
                "sw   zero, 24({d})",
                "sw   zero, 28({d})",
                d = in(reg) top,
                a = out(reg) _,
                acc = out(reg) _,
                options(nostack, preserves_flags),
            );
        }
    }
    #[cfg(not(target_os = "zkvm"))]
    {
        popn_top!([], op1, context.interpreter);
        *op1 = U256::from(op1.is_zero());
    }
}

/// Implements the AND instruction.
///
/// Bitwise AND of two values from stack.
pub fn bitand<WIRE: InterpreterTypes, H: ?Sized>(context: InstructionContext<'_, H, WIRE>) {
    #[cfg(target_os = "zkvm")]
    {
        if context.interpreter.stack.len() < 2 {
            context.interpreter.halt_underflow();
            return;
        }
        unsafe {
            let (dst, src) = context.interpreter.stack.top_pair_ptr_unchecked();
            let d = dst as *mut u32;
            let s = src as *const u32;
            core::arch::asm!(
                "lw   {a},  0({d})", "lw  {b},  0({s})", "and {a}, {a}, {b}", "sw  {a},  0({d})",
                "lw   {a},  4({d})", "lw  {b},  4({s})", "and {a}, {a}, {b}", "sw  {a},  4({d})",
                "lw   {a},  8({d})", "lw  {b},  8({s})", "and {a}, {a}, {b}", "sw  {a},  8({d})",
                "lw   {a}, 12({d})", "lw  {b}, 12({s})", "and {a}, {a}, {b}", "sw  {a}, 12({d})",
                "lw   {a}, 16({d})", "lw  {b}, 16({s})", "and {a}, {a}, {b}", "sw  {a}, 16({d})",
                "lw   {a}, 20({d})", "lw  {b}, 20({s})", "and {a}, {a}, {b}", "sw  {a}, 20({d})",
                "lw   {a}, 24({d})", "lw  {b}, 24({s})", "and {a}, {a}, {b}", "sw  {a}, 24({d})",
                "lw   {a}, 28({d})", "lw  {b}, 28({s})", "and {a}, {a}, {b}", "sw  {a}, 28({d})",
                d = in(reg) d,
                s = in(reg) s,
                a = out(reg) _,
                b = out(reg) _,
                options(nostack, preserves_flags),
            );
            context.interpreter.stack.shrink_unchecked(1);
        }
    }
    #[cfg(not(target_os = "zkvm"))]
    {
        popn_top!([op1], op2, context.interpreter);
        *op2 = op1 & *op2;
    }
}

/// Implements the OR instruction.
///
/// Bitwise OR of two values from stack.
pub fn bitor<WIRE: InterpreterTypes, H: ?Sized>(context: InstructionContext<'_, H, WIRE>) {
    #[cfg(target_os = "zkvm")]
    {
        if context.interpreter.stack.len() < 2 {
            context.interpreter.halt_underflow();
            return;
        }
        unsafe {
            let (dst, src) = context.interpreter.stack.top_pair_ptr_unchecked();
            let d = dst as *mut u32;
            let s = src as *const u32;
            core::arch::asm!(
                "lw   {a},  0({d})", "lw  {b},  0({s})", "or  {a}, {a}, {b}", "sw  {a},  0({d})",
                "lw   {a},  4({d})", "lw  {b},  4({s})", "or  {a}, {a}, {b}", "sw  {a},  4({d})",
                "lw   {a},  8({d})", "lw  {b},  8({s})", "or  {a}, {a}, {b}", "sw  {a},  8({d})",
                "lw   {a}, 12({d})", "lw  {b}, 12({s})", "or  {a}, {a}, {b}", "sw  {a}, 12({d})",
                "lw   {a}, 16({d})", "lw  {b}, 16({s})", "or  {a}, {a}, {b}", "sw  {a}, 16({d})",
                "lw   {a}, 20({d})", "lw  {b}, 20({s})", "or  {a}, {a}, {b}", "sw  {a}, 20({d})",
                "lw   {a}, 24({d})", "lw  {b}, 24({s})", "or  {a}, {a}, {b}", "sw  {a}, 24({d})",
                "lw   {a}, 28({d})", "lw  {b}, 28({s})", "or  {a}, {a}, {b}", "sw  {a}, 28({d})",
                d = in(reg) d,
                s = in(reg) s,
                a = out(reg) _,
                b = out(reg) _,
                options(nostack, preserves_flags),
            );
            context.interpreter.stack.shrink_unchecked(1);
        }
    }
    #[cfg(not(target_os = "zkvm"))]
    {
        popn_top!([op1], op2, context.interpreter);
        *op2 = op1 | *op2;
    }
}

/// Implements the XOR instruction.
///
/// Bitwise XOR of two values from stack.
pub fn bitxor<WIRE: InterpreterTypes, H: ?Sized>(context: InstructionContext<'_, H, WIRE>) {
    #[cfg(target_os = "zkvm")]
    {
        if context.interpreter.stack.len() < 2 {
            context.interpreter.halt_underflow();
            return;
        }
        unsafe {
            let (dst, src) = context.interpreter.stack.top_pair_ptr_unchecked();
            let d = dst as *mut u32;
            let s = src as *const u32;
            core::arch::asm!(
                "lw   {a},  0({d})", "lw  {b},  0({s})", "xor {a}, {a}, {b}", "sw  {a},  0({d})",
                "lw   {a},  4({d})", "lw  {b},  4({s})", "xor {a}, {a}, {b}", "sw  {a},  4({d})",
                "lw   {a},  8({d})", "lw  {b},  8({s})", "xor {a}, {a}, {b}", "sw  {a},  8({d})",
                "lw   {a}, 12({d})", "lw  {b}, 12({s})", "xor {a}, {a}, {b}", "sw  {a}, 12({d})",
                "lw   {a}, 16({d})", "lw  {b}, 16({s})", "xor {a}, {a}, {b}", "sw  {a}, 16({d})",
                "lw   {a}, 20({d})", "lw  {b}, 20({s})", "xor {a}, {a}, {b}", "sw  {a}, 20({d})",
                "lw   {a}, 24({d})", "lw  {b}, 24({s})", "xor {a}, {a}, {b}", "sw  {a}, 24({d})",
                "lw   {a}, 28({d})", "lw  {b}, 28({s})", "xor {a}, {a}, {b}", "sw  {a}, 28({d})",
                d = in(reg) d,
                s = in(reg) s,
                a = out(reg) _,
                b = out(reg) _,
                options(nostack, preserves_flags),
            );
            context.interpreter.stack.shrink_unchecked(1);
        }
    }
    #[cfg(not(target_os = "zkvm"))]
    {
        popn_top!([op1], op2, context.interpreter);
        *op2 = op1 ^ *op2;
    }
}

/// Implements the NOT instruction.
///
/// Bitwise NOT (negation) of the top stack value.
pub fn not<WIRE: InterpreterTypes, H: ?Sized>(context: InstructionContext<'_, H, WIRE>) {
    #[cfg(target_os = "zkvm")]
    {
        if context.interpreter.stack.len() < 1 {
            context.interpreter.halt_underflow();
            return;
        }
        unsafe {
            let top = context.interpreter.stack.top_ptr_unchecked() as *mut u32;
            core::arch::asm!(
                "lw   {a},  0({d})", "xori {a}, {a}, -1", "sw  {a},  0({d})",
                "lw   {a},  4({d})", "xori {a}, {a}, -1", "sw  {a},  4({d})",
                "lw   {a},  8({d})", "xori {a}, {a}, -1", "sw  {a},  8({d})",
                "lw   {a}, 12({d})", "xori {a}, {a}, -1", "sw  {a}, 12({d})",
                "lw   {a}, 16({d})", "xori {a}, {a}, -1", "sw  {a}, 16({d})",
                "lw   {a}, 20({d})", "xori {a}, {a}, -1", "sw  {a}, 20({d})",
                "lw   {a}, 24({d})", "xori {a}, {a}, -1", "sw  {a}, 24({d})",
                "lw   {a}, 28({d})", "xori {a}, {a}, -1", "sw  {a}, 28({d})",
                d = in(reg) top,
                a = out(reg) _,
                options(nostack, preserves_flags),
            );
        }
    }
    #[cfg(not(target_os = "zkvm"))]
    {
        popn_top!([], op1, context.interpreter);
        *op1 = !*op1;
    }
}

/// Implements the BYTE instruction.
///
/// Extracts a single byte from a word at a given index.
pub fn byte<WIRE: InterpreterTypes, H: ?Sized>(context: InstructionContext<'_, H, WIRE>) {
    popn_top!([op1], op2, context.interpreter);
    let o1 = as_usize_saturated!(op1);
    *op2 = if o1 < 32 {
        // `31 - o1` because `byte` returns LE, while we want BE
        U256::from(op2.byte(31 - o1))
    } else {
        U256::ZERO
    };
}

/// EIP-145: Bitwise shifting instructions in EVM
pub fn shl<WIRE: InterpreterTypes, H: ?Sized>(context: InstructionContext<'_, H, WIRE>) {
    check!(context.interpreter, CONSTANTINOPLE);
    popn_top!([op1], op2, context.interpreter);
    let shift = as_usize_saturated!(op1);
    *op2 = if shift < 256 {
        *op2 << shift
    } else {
        U256::ZERO
    }
}

/// EIP-145: Bitwise shifting instructions in EVM
pub fn shr<WIRE: InterpreterTypes, H: ?Sized>(context: InstructionContext<'_, H, WIRE>) {
    check!(context.interpreter, CONSTANTINOPLE);
    popn_top!([op1], op2, context.interpreter);
    let shift = as_usize_saturated!(op1);
    *op2 = if shift < 256 {
        *op2 >> shift
    } else {
        U256::ZERO
    }
}

/// EIP-145: Bitwise shifting instructions in EVM
pub fn sar<WIRE: InterpreterTypes, H: ?Sized>(context: InstructionContext<'_, H, WIRE>) {
    check!(context.interpreter, CONSTANTINOPLE);
    popn_top!([op1], op2, context.interpreter);
    let shift = as_usize_saturated!(op1);
    *op2 = if shift < 256 {
        op2.arithmetic_shr(shift)
    } else if op2.bit(255) {
        U256::MAX
    } else {
        U256::ZERO
    };
}

#[cfg(test)]
mod tests {
    use crate::{
        host::DummyHost,
        instructions::bitwise::{byte, clz, sar, shl, shr},
        InstructionContext, Interpreter,
    };
    use primitives::{hardfork::SpecId, uint, U256};

    #[test]
    fn test_shift_left() {
        let mut interpreter = Interpreter::default();

        struct TestCase {
            value: U256,
            shift: U256,
            expected: U256,
        }

        uint! {
            let test_cases = [
                TestCase {
                    value: 0x0000000000000000000000000000000000000000000000000000000000000001_U256,
                    shift: 0x00_U256,
                    expected: 0x0000000000000000000000000000000000000000000000000000000000000001_U256,
                },
                TestCase {
                    value: 0x0000000000000000000000000000000000000000000000000000000000000001_U256,
                    shift: 0x01_U256,
                    expected: 0x0000000000000000000000000000000000000000000000000000000000000002_U256,
                },
                TestCase {
                    value: 0x0000000000000000000000000000000000000000000000000000000000000001_U256,
                    shift: 0xff_U256,
                    expected: 0x8000000000000000000000000000000000000000000000000000000000000000_U256,
                },
                TestCase {
                    value: 0x0000000000000000000000000000000000000000000000000000000000000001_U256,
                    shift: 0x0100_U256,
                    expected: 0x0000000000000000000000000000000000000000000000000000000000000000_U256,
                },
                TestCase {
                    value: 0x0000000000000000000000000000000000000000000000000000000000000001_U256,
                    shift: 0x0101_U256,
                    expected: 0x0000000000000000000000000000000000000000000000000000000000000000_U256,
                },
                TestCase {
                    value: 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_U256,
                    shift: 0x00_U256,
                    expected: 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_U256,
                },
                TestCase {
                    value: 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_U256,
                    shift: 0x01_U256,
                    expected: 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe_U256,
                },
                TestCase {
                    value: 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_U256,
                    shift: 0xff_U256,
                    expected: 0x8000000000000000000000000000000000000000000000000000000000000000_U256,
                },
                TestCase {
                    value: 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_U256,
                    shift: 0x0100_U256,
                    expected: 0x0000000000000000000000000000000000000000000000000000000000000000_U256,
                },
                TestCase {
                    value: 0x0000000000000000000000000000000000000000000000000000000000000000_U256,
                    shift: 0x01_U256,
                    expected: 0x0000000000000000000000000000000000000000000000000000000000000000_U256,
                },
                TestCase {
                    value: 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_U256,
                    shift: 0x01_U256,
                    expected: 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe_U256,
                },
            ];
        }

        for test in test_cases {
            push!(interpreter, test.value);
            push!(interpreter, test.shift);
            let context = InstructionContext {
                host: &mut DummyHost::default(),
                interpreter: &mut interpreter,
            };
            shl(context);
            let res = interpreter.stack.pop().unwrap();
            assert_eq!(res, test.expected);
        }
    }

    #[test]
    fn test_logical_shift_right() {
        let mut interpreter = Interpreter::default();

        struct TestCase {
            value: U256,
            shift: U256,
            expected: U256,
        }

        uint! {
            let test_cases = [
                TestCase {
                    value: 0x0000000000000000000000000000000000000000000000000000000000000001_U256,
                    shift: 0x00_U256,
                    expected: 0x0000000000000000000000000000000000000000000000000000000000000001_U256,
                },
                TestCase {
                    value: 0x0000000000000000000000000000000000000000000000000000000000000001_U256,
                    shift: 0x01_U256,
                    expected: 0x0000000000000000000000000000000000000000000000000000000000000000_U256,
                },
                TestCase {
                    value: 0x8000000000000000000000000000000000000000000000000000000000000000_U256,
                    shift: 0x01_U256,
                    expected: 0x4000000000000000000000000000000000000000000000000000000000000000_U256,
                },
                TestCase {
                    value: 0x8000000000000000000000000000000000000000000000000000000000000000_U256,
                    shift: 0xff_U256,
                    expected: 0x0000000000000000000000000000000000000000000000000000000000000001_U256,
                },
                TestCase {
                    value: 0x8000000000000000000000000000000000000000000000000000000000000000_U256,
                    shift: 0x0100_U256,
                    expected: 0x0000000000000000000000000000000000000000000000000000000000000000_U256,
                },
                TestCase {
                    value: 0x8000000000000000000000000000000000000000000000000000000000000000_U256,
                    shift: 0x0101_U256,
                    expected: 0x0000000000000000000000000000000000000000000000000000000000000000_U256,
                },
                TestCase {
                    value: 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_U256,
                    shift: 0x00_U256,
                    expected: 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_U256,
                },
                TestCase {
                    value: 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_U256,
                    shift: 0x01_U256,
                    expected: 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_U256,
                },
                TestCase {
                    value: 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_U256,
                    shift: 0xff_U256,
                    expected: 0x0000000000000000000000000000000000000000000000000000000000000001_U256,
                },
                TestCase {
                    value: 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_U256,
                    shift: 0x0100_U256,
                    expected: 0x0000000000000000000000000000000000000000000000000000000000000000_U256,
                },
                TestCase {
                    value: 0x0000000000000000000000000000000000000000000000000000000000000000_U256,
                    shift: 0x01_U256,
                    expected: 0x0000000000000000000000000000000000000000000000000000000000000000_U256,
                },
            ];
        }

        for test in test_cases {
            push!(interpreter, test.value);
            push!(interpreter, test.shift);
            let context = InstructionContext {
                host: &mut DummyHost::default(),
                interpreter: &mut interpreter,
            };
            shr(context);
            let res = interpreter.stack.pop().unwrap();
            assert_eq!(res, test.expected);
        }
    }

    #[test]
    fn test_arithmetic_shift_right() {
        let mut interpreter = Interpreter::default();

        struct TestCase {
            value: U256,
            shift: U256,
            expected: U256,
        }

        uint! {
        let test_cases = [
            TestCase {
                value: 0x0000000000000000000000000000000000000000000000000000000000000001_U256,
                shift: 0x00_U256,
                expected: 0x0000000000000000000000000000000000000000000000000000000000000001_U256,
            },
            TestCase {
                value: 0x0000000000000000000000000000000000000000000000000000000000000001_U256,
                shift: 0x01_U256,
                expected: 0x0000000000000000000000000000000000000000000000000000000000000000_U256,
            },
            TestCase {
                value: 0x8000000000000000000000000000000000000000000000000000000000000000_U256,
                shift: 0x01_U256,
                expected: 0xc000000000000000000000000000000000000000000000000000000000000000_U256,
            },
            TestCase {
                value: 0x8000000000000000000000000000000000000000000000000000000000000000_U256,
                shift: 0xff_U256,
                expected: 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_U256,
            },
            TestCase {
                value: 0x8000000000000000000000000000000000000000000000000000000000000000_U256,
                shift: 0x0100_U256,
                expected: 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_U256,
            },
            TestCase {
                value: 0x8000000000000000000000000000000000000000000000000000000000000000_U256,
                shift: 0x0101_U256,
                expected: 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_U256,
            },
            TestCase {
                value: 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_U256,
                shift: 0x00_U256,
                expected: 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_U256,
            },
            TestCase {
                value: 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_U256,
                shift: 0x01_U256,
                expected: 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_U256,
            },
            TestCase {
                value: 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_U256,
                shift: 0xff_U256,
                expected: 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_U256,
            },
            TestCase {
                value: 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_U256,
                shift: 0x0100_U256,
                expected: 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_U256,
            },
            TestCase {
                value: 0x0000000000000000000000000000000000000000000000000000000000000000_U256,
                shift: 0x01_U256,
                expected: 0x0000000000000000000000000000000000000000000000000000000000000000_U256,
            },
            TestCase {
                value: 0x4000000000000000000000000000000000000000000000000000000000000000_U256,
                shift: 0xfe_U256,
                expected: 0x0000000000000000000000000000000000000000000000000000000000000001_U256,
            },
            TestCase {
                value: 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_U256,
                shift: 0xf8_U256,
                expected: 0x000000000000000000000000000000000000000000000000000000000000007f_U256,
            },
            TestCase {
                value: 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_U256,
                shift: 0xfe_U256,
                expected: 0x0000000000000000000000000000000000000000000000000000000000000001_U256,
            },
            TestCase {
                value: 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_U256,
                shift: 0xff_U256,
                expected: 0x0000000000000000000000000000000000000000000000000000000000000000_U256,
            },
            TestCase {
                value: 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_U256,
                shift: 0x0100_U256,
                expected: 0x0000000000000000000000000000000000000000000000000000000000000000_U256,
            },
        ];
            }

        for test in test_cases {
            push!(interpreter, test.value);
            push!(interpreter, test.shift);
            let context = InstructionContext {
                host: &mut DummyHost::default(),
                interpreter: &mut interpreter,
            };
            sar(context);
            let res = interpreter.stack.pop().unwrap();
            assert_eq!(res, test.expected);
        }
    }

    #[test]
    fn test_byte() {
        struct TestCase {
            input: U256,
            index: usize,
            expected: U256,
        }

        let mut interpreter = Interpreter::default();

        let input_value = U256::from(0x1234567890abcdef1234567890abcdef_u128);
        let test_cases = (0..32)
            .map(|i| {
                let byte_pos = 31 - i;

                let shift_amount = U256::from(byte_pos * 8);
                let byte_value = (input_value >> shift_amount) & U256::from(0xFF);
                TestCase {
                    input: input_value,
                    index: i,
                    expected: byte_value,
                }
            })
            .collect::<Vec<_>>();

        for test in test_cases.iter() {
            push!(interpreter, test.input);
            push!(interpreter, U256::from(test.index));
            let context = InstructionContext {
                host: &mut DummyHost::default(),
                interpreter: &mut interpreter,
            };
            byte(context);
            let res = interpreter.stack.pop().unwrap();
            assert_eq!(res, test.expected, "Failed at index: {}", test.index);
        }
    }

    #[test]
    fn test_clz() {
        let mut interpreter = Interpreter::default();
        interpreter.runtime_flag.spec_id = SpecId::OSAKA;
        let mut host = DummyHost::new(SpecId::OSAKA);

        struct TestCase {
            value: U256,
            expected: U256,
        }

        uint! {
            let test_cases = [
                TestCase { value: 0x0_U256, expected: 256_U256 },
                TestCase { value: 0x1_U256, expected: 255_U256 },
                TestCase { value: 0x2_U256, expected: 254_U256 },
                TestCase { value: 0x3_U256, expected: 254_U256 },
                TestCase { value: 0x4_U256, expected: 253_U256 },
                TestCase { value: 0x7_U256, expected: 253_U256 },
                TestCase { value: 0x8_U256, expected: 252_U256 },
                TestCase { value: 0xff_U256, expected: 248_U256 },
                TestCase { value: 0x100_U256, expected: 247_U256 },
                TestCase { value: 0xffff_U256, expected: 240_U256 },
                TestCase {
                    value: 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_U256, // U256::MAX
                    expected: 0_U256,
                },
                TestCase {
                    value: 0x8000000000000000000000000000000000000000000000000000000000000000_U256, // 1 << 255
                    expected: 0_U256,
                },
                TestCase { // Smallest value with 1 leading zero
                    value: 0x4000000000000000000000000000000000000000000000000000000000000000_U256, // 1 << 254
                    expected: 1_U256,
                },
                TestCase { // Value just below 1 << 255
                    value: 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_U256,
                    expected: 1_U256,
                },
            ];
        }

        for test in test_cases {
            push!(interpreter, test.value);
            let context = InstructionContext {
                host: &mut host,
                interpreter: &mut interpreter,
            };
            clz(context);
            let res = interpreter.stack.pop().unwrap();
            assert_eq!(
                res, test.expected,
                "CLZ for value {:#x} failed. Expected: {}, Got: {}",
                test.value, test.expected, res
            );
        }
    }
}
