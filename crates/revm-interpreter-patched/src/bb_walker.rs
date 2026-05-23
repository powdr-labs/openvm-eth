//! Generic basic-block walker. Executes a pre-analyzed pure BB by reading
//! opcodes from bytecode and dispatching via a small match. Saves per-opcode
//! static gas checks (batched up front) and per-opcode table lookups.

use crate::{
    instructions::{arithmetic, bitwise, control, memory, stack as stack_ops, system},
    interpreter_types::{Jumps, LoopControl, StackTr},
    Host, InstructionContext, InstructionResult, Interpreter, InterpreterTypes,
};

/// Compact descriptor of a pure basic block: bytes consumed in bytecode,
/// total static gas, stack-bounds pre-check thresholds.
#[derive(Debug, Clone, Copy)]
pub struct BbDesc {
    /// Total number of bytecode bytes consumed (opcodes + their immediates).
    pub byte_len: u16,
    /// Sum of static gas costs over every opcode in the BB.
    pub total_gas: u32,
    /// Minimum stack depth required at entry (no opcode underflows).
    pub min_stack: u16,
    /// Maximum stack growth at any point during the BB.
    pub max_growth: u16,
}

/// Walks `desc.byte_len` bytes of bytecode starting at the current pc and
/// dispatches each pure opcode. Returns when the BB ends. For non-terminator
/// BBs, pc lands at the next opcode after the last byte. For terminator BBs
/// (JUMP/JUMPI/STOP/INVALID), the terminator handler sets pc / halts.
#[inline]
pub fn run_bb<W: InterpreterTypes, H: Host + ?Sized>(
    interp: &mut Interpreter<W>,
    host: &mut H,
    desc: &BbDesc,
) {
    // Stack pre-check.
    let len = interp.stack.len();
    if len < desc.min_stack as usize {
        return interp.halt_underflow();
    }
    if len + desc.max_growth as usize > crate::STACK_LIMIT {
        return interp.halt_overflow();
    }
    // Gas pre-charge.
    if !interp.gas.record_cost(desc.total_gas as u64) {
        return interp.halt_oog();
    }

    let mut remaining = desc.byte_len as isize;
    while remaining > 0 {
        // SAFETY: instruction_pointer is always within bytecode bytes.
        let opcode = interp.bytecode.opcode();
        // Advance past opcode byte.
        interp.bytecode.relative_jump(1);
        remaining -= 1;

        match opcode {
            // Stop / Invalid: halt and return.
            0x00 => {
                control::stop(InstructionContext { interpreter: interp, host });
                return;
            }
            0xFE => {
                control::invalid(InstructionContext { interpreter: interp, host });
                return;
            }
            // Arithmetic.
            0x01 => arithmetic::add(InstructionContext { interpreter: interp, host }),
            0x02 => arithmetic::mul(InstructionContext { interpreter: interp, host }),
            0x03 => arithmetic::sub(InstructionContext { interpreter: interp, host }),
            0x04 => arithmetic::div(InstructionContext { interpreter: interp, host }),
            0x05 => arithmetic::sdiv(InstructionContext { interpreter: interp, host }),
            0x06 => arithmetic::rem(InstructionContext { interpreter: interp, host }),
            0x07 => arithmetic::smod(InstructionContext { interpreter: interp, host }),
            0x08 => arithmetic::addmod(InstructionContext { interpreter: interp, host }),
            0x09 => arithmetic::mulmod(InstructionContext { interpreter: interp, host }),
            0x0B => arithmetic::signextend(InstructionContext { interpreter: interp, host }),
            // Comparison.
            0x10 => bitwise::lt(InstructionContext { interpreter: interp, host }),
            0x11 => bitwise::gt(InstructionContext { interpreter: interp, host }),
            0x12 => bitwise::slt(InstructionContext { interpreter: interp, host }),
            0x13 => bitwise::sgt(InstructionContext { interpreter: interp, host }),
            0x14 => bitwise::eq(InstructionContext { interpreter: interp, host }),
            0x15 => bitwise::iszero(InstructionContext { interpreter: interp, host }),
            // Bitwise.
            0x16 => bitwise::bitand(InstructionContext { interpreter: interp, host }),
            0x17 => bitwise::bitor(InstructionContext { interpreter: interp, host }),
            0x18 => bitwise::bitxor(InstructionContext { interpreter: interp, host }),
            0x19 => bitwise::not(InstructionContext { interpreter: interp, host }),
            0x1A => bitwise::byte(InstructionContext { interpreter: interp, host }),
            0x1B => bitwise::shl(InstructionContext { interpreter: interp, host }),
            0x1C => bitwise::shr(InstructionContext { interpreter: interp, host }),
            0x1D => bitwise::sar(InstructionContext { interpreter: interp, host }),
            // Stack.
            0x50 => stack_ops::pop(InstructionContext { interpreter: interp, host }),
            // PUSH0..PUSH32 (0x5F..=0x7F). PUSH0 has a dedicated function
            // that pushes U256::ZERO; the parameterized push::<0> would
            // be a no-op on an empty slice.
            0x5F => stack_ops::push0(InstructionContext { interpreter: interp, host }),
            0x60 => {
                stack_ops::push::<1, _, _>(InstructionContext { interpreter: interp, host });
                remaining -= 1;
            }
            0x61 => {
                stack_ops::push::<2, _, _>(InstructionContext { interpreter: interp, host });
                remaining -= 2;
            }
            0x62 => {
                stack_ops::push::<3, _, _>(InstructionContext { interpreter: interp, host });
                remaining -= 3;
            }
            0x63 => {
                stack_ops::push::<4, _, _>(InstructionContext { interpreter: interp, host });
                remaining -= 4;
            }
            0x64 => {
                stack_ops::push::<5, _, _>(InstructionContext { interpreter: interp, host });
                remaining -= 5;
            }
            0x65 => {
                stack_ops::push::<6, _, _>(InstructionContext { interpreter: interp, host });
                remaining -= 6;
            }
            0x66 => {
                stack_ops::push::<7, _, _>(InstructionContext { interpreter: interp, host });
                remaining -= 7;
            }
            0x67 => {
                stack_ops::push::<8, _, _>(InstructionContext { interpreter: interp, host });
                remaining -= 8;
            }
            0x68 => {
                stack_ops::push::<9, _, _>(InstructionContext { interpreter: interp, host });
                remaining -= 9;
            }
            0x69 => {
                stack_ops::push::<10, _, _>(InstructionContext { interpreter: interp, host });
                remaining -= 10;
            }
            0x6A => {
                stack_ops::push::<11, _, _>(InstructionContext { interpreter: interp, host });
                remaining -= 11;
            }
            0x6B => {
                stack_ops::push::<12, _, _>(InstructionContext { interpreter: interp, host });
                remaining -= 12;
            }
            0x6C => {
                stack_ops::push::<13, _, _>(InstructionContext { interpreter: interp, host });
                remaining -= 13;
            }
            0x6D => {
                stack_ops::push::<14, _, _>(InstructionContext { interpreter: interp, host });
                remaining -= 14;
            }
            0x6E => {
                stack_ops::push::<15, _, _>(InstructionContext { interpreter: interp, host });
                remaining -= 15;
            }
            0x6F => {
                stack_ops::push::<16, _, _>(InstructionContext { interpreter: interp, host });
                remaining -= 16;
            }
            0x70 => {
                stack_ops::push::<17, _, _>(InstructionContext { interpreter: interp, host });
                remaining -= 17;
            }
            0x71 => {
                stack_ops::push::<18, _, _>(InstructionContext { interpreter: interp, host });
                remaining -= 18;
            }
            0x72 => {
                stack_ops::push::<19, _, _>(InstructionContext { interpreter: interp, host });
                remaining -= 19;
            }
            0x73 => {
                stack_ops::push::<20, _, _>(InstructionContext { interpreter: interp, host });
                remaining -= 20;
            }
            0x74 => {
                stack_ops::push::<21, _, _>(InstructionContext { interpreter: interp, host });
                remaining -= 21;
            }
            0x75 => {
                stack_ops::push::<22, _, _>(InstructionContext { interpreter: interp, host });
                remaining -= 22;
            }
            0x76 => {
                stack_ops::push::<23, _, _>(InstructionContext { interpreter: interp, host });
                remaining -= 23;
            }
            0x77 => {
                stack_ops::push::<24, _, _>(InstructionContext { interpreter: interp, host });
                remaining -= 24;
            }
            0x78 => {
                stack_ops::push::<25, _, _>(InstructionContext { interpreter: interp, host });
                remaining -= 25;
            }
            0x79 => {
                stack_ops::push::<26, _, _>(InstructionContext { interpreter: interp, host });
                remaining -= 26;
            }
            0x7A => {
                stack_ops::push::<27, _, _>(InstructionContext { interpreter: interp, host });
                remaining -= 27;
            }
            0x7B => {
                stack_ops::push::<28, _, _>(InstructionContext { interpreter: interp, host });
                remaining -= 28;
            }
            0x7C => {
                stack_ops::push::<29, _, _>(InstructionContext { interpreter: interp, host });
                remaining -= 29;
            }
            0x7D => {
                stack_ops::push::<30, _, _>(InstructionContext { interpreter: interp, host });
                remaining -= 30;
            }
            0x7E => {
                stack_ops::push::<31, _, _>(InstructionContext { interpreter: interp, host });
                remaining -= 31;
            }
            0x7F => {
                stack_ops::push::<32, _, _>(InstructionContext { interpreter: interp, host });
                remaining -= 32;
            }
            // DUP1..DUP16 (0x80..=0x8F).
            0x80 => stack_ops::dup::<1, _, _>(InstructionContext { interpreter: interp, host }),
            0x81 => stack_ops::dup::<2, _, _>(InstructionContext { interpreter: interp, host }),
            0x82 => stack_ops::dup::<3, _, _>(InstructionContext { interpreter: interp, host }),
            0x83 => stack_ops::dup::<4, _, _>(InstructionContext { interpreter: interp, host }),
            0x84 => stack_ops::dup::<5, _, _>(InstructionContext { interpreter: interp, host }),
            0x85 => stack_ops::dup::<6, _, _>(InstructionContext { interpreter: interp, host }),
            0x86 => stack_ops::dup::<7, _, _>(InstructionContext { interpreter: interp, host }),
            0x87 => stack_ops::dup::<8, _, _>(InstructionContext { interpreter: interp, host }),
            0x88 => stack_ops::dup::<9, _, _>(InstructionContext { interpreter: interp, host }),
            0x89 => stack_ops::dup::<10, _, _>(InstructionContext { interpreter: interp, host }),
            0x8A => stack_ops::dup::<11, _, _>(InstructionContext { interpreter: interp, host }),
            0x8B => stack_ops::dup::<12, _, _>(InstructionContext { interpreter: interp, host }),
            0x8C => stack_ops::dup::<13, _, _>(InstructionContext { interpreter: interp, host }),
            0x8D => stack_ops::dup::<14, _, _>(InstructionContext { interpreter: interp, host }),
            0x8E => stack_ops::dup::<15, _, _>(InstructionContext { interpreter: interp, host }),
            0x8F => stack_ops::dup::<16, _, _>(InstructionContext { interpreter: interp, host }),
            // SWAP1..SWAP16 (0x90..=0x9F).
            0x90 => stack_ops::swap::<1, _, _>(InstructionContext { interpreter: interp, host }),
            0x91 => stack_ops::swap::<2, _, _>(InstructionContext { interpreter: interp, host }),
            0x92 => stack_ops::swap::<3, _, _>(InstructionContext { interpreter: interp, host }),
            0x93 => stack_ops::swap::<4, _, _>(InstructionContext { interpreter: interp, host }),
            0x94 => stack_ops::swap::<5, _, _>(InstructionContext { interpreter: interp, host }),
            0x95 => stack_ops::swap::<6, _, _>(InstructionContext { interpreter: interp, host }),
            0x96 => stack_ops::swap::<7, _, _>(InstructionContext { interpreter: interp, host }),
            0x97 => stack_ops::swap::<8, _, _>(InstructionContext { interpreter: interp, host }),
            0x98 => stack_ops::swap::<9, _, _>(InstructionContext { interpreter: interp, host }),
            0x99 => stack_ops::swap::<10, _, _>(InstructionContext { interpreter: interp, host }),
            0x9A => stack_ops::swap::<11, _, _>(InstructionContext { interpreter: interp, host }),
            0x9B => stack_ops::swap::<12, _, _>(InstructionContext { interpreter: interp, host }),
            0x9C => stack_ops::swap::<13, _, _>(InstructionContext { interpreter: interp, host }),
            0x9D => stack_ops::swap::<14, _, _>(InstructionContext { interpreter: interp, host }),
            0x9E => stack_ops::swap::<15, _, _>(InstructionContext { interpreter: interp, host }),
            0x9F => stack_ops::swap::<16, _, _>(InstructionContext { interpreter: interp, host }),
            // Misc pure.
            0x58 => control::pc(InstructionContext { interpreter: interp, host }),
            0x59 => memory::msize(InstructionContext { interpreter: interp, host }),
            0x5A => system::gas(InstructionContext { interpreter: interp, host }),
            0x5B => { /* JUMPDEST no-op */ }
            // Terminators: JUMP / JUMPI. These advance pc themselves.
            0x56 => {
                control::jump(InstructionContext { interpreter: interp, host });
                return;
            }
            0x57 => {
                control::jumpi(InstructionContext { interpreter: interp, host });
                return;
            }
            _ => {
                // Should never happen if the transpiler classified this BB
                // as pure. Halt with InvalidFEOpcode to be safe.
                interp.halt(InstructionResult::InvalidFEOpcode);
                return;
            }
        }
        if !interp.bytecode.is_not_end() {
            return;
        }
    }
}
