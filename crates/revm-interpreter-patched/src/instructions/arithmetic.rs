use super::i256::{i256_div, i256_mod};
use crate::{
    interpreter_types::{InterpreterTypes, StackTr},
    InstructionContext,
};
use context_interface::Host;
use primitives::U256;

/// Implements the ADD instruction - adds two values from stack.
pub fn add<WIRE: InterpreterTypes, H: ?Sized>(context: InstructionContext<'_, H, WIRE>) {
    // openvm: transpiled EVM ADD. Reads stack[len-1] and stack[len-2] directly,
    // does an 8-limb (32-bit) carry-propagating addc chain in place at
    // stack[len-2], decrements stack length. No popn_top local copy, no
    // custom opcodes — pure RV32IM that an unmodified RV32IM core would
    // execute identically. U256 limbs are LE; carry walks offset 0 -> 28.
    #[cfg(target_os = "zkvm")]
    unsafe {
        if context.interpreter.stack.len() < 2 {
            context.interpreter.halt_underflow();
            return;
        }
        let (dst_u256, src_u256) = context.interpreter.stack.top_pair_ptr_unchecked();
        let d = dst_u256 as *mut u32;
        let s = src_u256 as *const u32;
        core::arch::asm!(
            // limb 0: no incoming carry; t3 holds outgoing carry.
            "lw   t0, 0({d})",  "lw   t1, 0({s})",
            "add  t2, t0, t1",  "sltu t3, t2, t0",
            "sw   t2, 0({d})",
            // limbs 1..=6: incoming carry in t3, outgoing carry in t3.
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
            // limb 7: incoming carry in t3, outgoing carry discarded (wrap).
            "lw   t0, 28({d})", "lw   t1, 28({s})",
            "add  t2, t0, t1",
            "add  t2, t2, t3",
            "sw   t2, 28({d})",

            d = in(reg) d,
            s = in(reg) s,
            out("t0") _, out("t1") _, out("t2") _,
            out("t3") _, out("t4") _, out("t5") _,
            options(nostack, preserves_flags),
        );
        context.interpreter.stack.shrink_unchecked(1);
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
    popn_top!([op1], op2, context.interpreter);
    *op2 = op1.wrapping_sub(*op2);
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
