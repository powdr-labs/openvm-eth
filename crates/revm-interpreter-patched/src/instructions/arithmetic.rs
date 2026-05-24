use super::i256::{i256_div, i256_mod};
use crate::{
    interpreter_types::{InterpreterTypes, StackTr},
    InstructionContext,
};
use context_interface::Host;
use primitives::U256;

/// Implements the ADD instruction - adds two values from stack.
pub fn add<WIRE: InterpreterTypes, H: ?Sized>(context: InstructionContext<'_, H, WIRE>) {
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
            // Hand-rolled 8-limb add-with-carry on RV32IM. d += s.
            core::arch::asm!(
                // limb 0 (no carry-in)
                "lw   {a},  0({d})",
                "lw   {b},  0({s})",
                "add  {a}, {a}, {b}",
                "sw   {a},  0({d})",
                "sltu {c}, {a}, {b}",
                // limb 1
                "lw   {a},  4({d})",
                "lw   {b},  4({s})",
                "add  {a}, {a}, {b}",
                "sltu {t}, {a}, {b}",
                "add  {a}, {a}, {c}",
                "sltu {c}, {a}, {c}",
                "or   {c}, {c}, {t}",
                "sw   {a},  4({d})",
                // limb 2
                "lw   {a},  8({d})",
                "lw   {b},  8({s})",
                "add  {a}, {a}, {b}",
                "sltu {t}, {a}, {b}",
                "add  {a}, {a}, {c}",
                "sltu {c}, {a}, {c}",
                "or   {c}, {c}, {t}",
                "sw   {a},  8({d})",
                // limb 3
                "lw   {a}, 12({d})",
                "lw   {b}, 12({s})",
                "add  {a}, {a}, {b}",
                "sltu {t}, {a}, {b}",
                "add  {a}, {a}, {c}",
                "sltu {c}, {a}, {c}",
                "or   {c}, {c}, {t}",
                "sw   {a}, 12({d})",
                // limb 4
                "lw   {a}, 16({d})",
                "lw   {b}, 16({s})",
                "add  {a}, {a}, {b}",
                "sltu {t}, {a}, {b}",
                "add  {a}, {a}, {c}",
                "sltu {c}, {a}, {c}",
                "or   {c}, {c}, {t}",
                "sw   {a}, 16({d})",
                // limb 5
                "lw   {a}, 20({d})",
                "lw   {b}, 20({s})",
                "add  {a}, {a}, {b}",
                "sltu {t}, {a}, {b}",
                "add  {a}, {a}, {c}",
                "sltu {c}, {a}, {c}",
                "or   {c}, {c}, {t}",
                "sw   {a}, 20({d})",
                // limb 6
                "lw   {a}, 24({d})",
                "lw   {b}, 24({s})",
                "add  {a}, {a}, {b}",
                "sltu {t}, {a}, {b}",
                "add  {a}, {a}, {c}",
                "sltu {c}, {a}, {c}",
                "or   {c}, {c}, {t}",
                "sw   {a}, 24({d})",
                // limb 7 (no carry-out needed; result wraps mod 2^256)
                "lw   {a}, 28({d})",
                "lw   {b}, 28({s})",
                "add  {a}, {a}, {b}",
                "add  {a}, {a}, {c}",
                "sw   {a}, 28({d})",
                d = in(reg) d,
                s = in(reg) s,
                a = out(reg) _,
                b = out(reg) _,
                c = out(reg) _,
                t = out(reg) _,
                options(nostack, preserves_flags),
            );
            context.interpreter.stack.shrink_unchecked(1);
        }
    }
    #[cfg(not(target_os = "zkvm"))]
    {
        popn_top!([op1], op2, context.interpreter);
        *op2 = op1.wrapping_add(*op2);
    }
}

/// Implements the MUL instruction - multiplies two values from stack.
pub fn mul<WIRE: InterpreterTypes, H: ?Sized>(context: InstructionContext<'_, H, WIRE>) {
    popn_top!([op1], op2, context.interpreter);
    *op2 = op1.wrapping_mul(*op2);
}

/// Implements the SUB instruction - subtracts two values from stack.
pub fn sub<WIRE: InterpreterTypes, H: ?Sized>(context: InstructionContext<'_, H, WIRE>) {
    #[cfg(target_os = "zkvm")]
    {
        if context.interpreter.stack.len() < 2 {
            context.interpreter.halt_underflow();
            return;
        }
        unsafe {
            let (dst, src) = context.interpreter.stack.top_pair_ptr_unchecked();
            // EVM SUB: result = popped_top - new_top = src - dst (stored into dst).
            let d = dst as *mut u32;
            let s = src as *const u32;
            // Hand-rolled 8-limb sub-with-borrow on RV32IM. d = s - d.
            core::arch::asm!(
                // limb 0 (no borrow-in)
                "lw   {sw},  0({s})",
                "lw   {dw},  0({d})",
                "sltu {c}, {sw}, {dw}",
                "sub  {a}, {sw}, {dw}",
                "sw   {a},  0({d})",
                // limb 1
                "lw   {sw},  4({s})",
                "lw   {dw},  4({d})",
                "sltu {t}, {sw}, {dw}",
                "sub  {a}, {sw}, {dw}",
                "sltu {u}, {a}, {c}",
                "sub  {a}, {a}, {c}",
                "or   {c}, {t}, {u}",
                "sw   {a},  4({d})",
                // limb 2
                "lw   {sw},  8({s})",
                "lw   {dw},  8({d})",
                "sltu {t}, {sw}, {dw}",
                "sub  {a}, {sw}, {dw}",
                "sltu {u}, {a}, {c}",
                "sub  {a}, {a}, {c}",
                "or   {c}, {t}, {u}",
                "sw   {a},  8({d})",
                // limb 3
                "lw   {sw}, 12({s})",
                "lw   {dw}, 12({d})",
                "sltu {t}, {sw}, {dw}",
                "sub  {a}, {sw}, {dw}",
                "sltu {u}, {a}, {c}",
                "sub  {a}, {a}, {c}",
                "or   {c}, {t}, {u}",
                "sw   {a}, 12({d})",
                // limb 4
                "lw   {sw}, 16({s})",
                "lw   {dw}, 16({d})",
                "sltu {t}, {sw}, {dw}",
                "sub  {a}, {sw}, {dw}",
                "sltu {u}, {a}, {c}",
                "sub  {a}, {a}, {c}",
                "or   {c}, {t}, {u}",
                "sw   {a}, 16({d})",
                // limb 5
                "lw   {sw}, 20({s})",
                "lw   {dw}, 20({d})",
                "sltu {t}, {sw}, {dw}",
                "sub  {a}, {sw}, {dw}",
                "sltu {u}, {a}, {c}",
                "sub  {a}, {a}, {c}",
                "or   {c}, {t}, {u}",
                "sw   {a}, 20({d})",
                // limb 6
                "lw   {sw}, 24({s})",
                "lw   {dw}, 24({d})",
                "sltu {t}, {sw}, {dw}",
                "sub  {a}, {sw}, {dw}",
                "sltu {u}, {a}, {c}",
                "sub  {a}, {a}, {c}",
                "or   {c}, {t}, {u}",
                "sw   {a}, 24({d})",
                // limb 7 (no borrow-out)
                "lw   {sw}, 28({s})",
                "lw   {dw}, 28({d})",
                "sub  {a}, {sw}, {dw}",
                "sub  {a}, {a}, {c}",
                "sw   {a}, 28({d})",
                d = in(reg) d,
                s = in(reg) s,
                a = out(reg) _,
                sw = out(reg) _,
                dw = out(reg) _,
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
        *op2 = op1.wrapping_sub(*op2);
    }
}

/// Implements the DIV instruction - divides two values from stack.
pub fn div<WIRE: InterpreterTypes, H: ?Sized>(context: InstructionContext<'_, H, WIRE>) {
    popn_top!([op1], op2, context.interpreter);
    if !op2.is_zero() {
        *op2 = op1.wrapping_div(*op2);
    }
}

/// Implements the SDIV instruction.
///
/// Performs signed division of two values from stack.
pub fn sdiv<WIRE: InterpreterTypes, H: ?Sized>(context: InstructionContext<'_, H, WIRE>) {
    popn_top!([op1], op2, context.interpreter);
    *op2 = i256_div(op1, *op2);
}

/// Implements the MOD instruction.
///
/// Pops two values from stack and pushes the remainder of their division.
pub fn rem<WIRE: InterpreterTypes, H: ?Sized>(context: InstructionContext<'_, H, WIRE>) {
    popn_top!([op1], op2, context.interpreter);
    if !op2.is_zero() {
        *op2 = op1.wrapping_rem(*op2);
    }
}

/// Implements the SMOD instruction.
///
/// Performs signed modulo of two values from stack.
pub fn smod<WIRE: InterpreterTypes, H: ?Sized>(context: InstructionContext<'_, H, WIRE>) {
    popn_top!([op1], op2, context.interpreter);
    *op2 = i256_mod(op1, *op2)
}

/// Implements the ADDMOD instruction.
///
/// Pops three values from stack and pushes (a + b) % n.
pub fn addmod<WIRE: InterpreterTypes, H: ?Sized>(context: InstructionContext<'_, H, WIRE>) {
    popn_top!([op1, op2], op3, context.interpreter);
    *op3 = op1.add_mod(op2, *op3)
}

/// Implements the MULMOD instruction.
///
/// Pops three values from stack and pushes (a * b) % n.
pub fn mulmod<WIRE: InterpreterTypes, H: ?Sized>(context: InstructionContext<'_, H, WIRE>) {
    popn_top!([op1, op2], op3, context.interpreter);
    *op3 = op1.mul_mod(op2, *op3)
}

/// Implements the EXP instruction - exponentiates two values from stack.
pub fn exp<WIRE: InterpreterTypes, H: Host + ?Sized>(context: InstructionContext<'_, H, WIRE>) {
    popn_top!([op1], op2, context.interpreter);
    gas!(
        context.interpreter,
        context.host.gas_params().exp_cost(*op2)
    );
    *op2 = op1.pow(*op2);
}

/// Implements the `SIGNEXTEND` opcode as defined in the Ethereum Yellow Paper.
///
/// In the yellow paper `SIGNEXTEND` is defined to take two inputs, we will call them
/// `x` and `y`, and produce one output.
///
/// The first `t` bits of the output (numbering from the left, starting from 0) are
/// equal to the `t`-th bit of `y`, where `t` is equal to `256 - 8(x + 1)`.
///
/// The remaining bits of the output are equal to the corresponding bits of `y`.
///
/// **Note**: If `x >= 32` then the output is equal to `y` since `t <= 0`.
///
/// To efficiently implement this algorithm in the case `x < 32` we do the following.
///
/// Let `b` be equal to the `t`-th bit of `y` and let `s = 255 - t = 8x + 7`
/// (this is effectively the same index as `t`, but numbering the bits from the
/// right instead of the left).
///
/// We can create a bit mask which is all zeros up to and including the `t`-th bit,
/// and all ones afterwards by computing the quantity `2^s - 1`.
///
/// We can use this mask to compute the output depending on the value of `b`.
///
/// If `b == 1` then the yellow paper says the output should be all ones up to
/// and including the `t`-th bit, followed by the remaining bits of `y`; this is equal to
/// `y | !mask` where `|` is the bitwise `OR` and `!` is bitwise negation.
///
/// Similarly, if `b == 0` then the yellow paper says the output should start with all zeros,
/// then end with bits from `b`; this is equal to `y & mask` where `&` is bitwise `AND`.
pub fn signextend<WIRE: InterpreterTypes, H: ?Sized>(context: InstructionContext<'_, H, WIRE>) {
    popn_top!([ext], x, context.interpreter);
    // For 31 we also don't need to do anything.
    if ext < U256::from(31) {
        let ext = ext.as_limbs()[0];
        let bit_index = (8 * ext + 7) as usize;
        let bit = x.bit(bit_index);
        let mask = (U256::from(1) << bit_index) - U256::from(1);
        *x = if bit { *x | !mask } else { *x & mask };
    }
}
