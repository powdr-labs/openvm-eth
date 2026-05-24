use crate::interpreter_types::{InterpreterTypes, MemoryTr, RuntimeFlag, StackTr};
use context_interface::Host;
use core::cmp::max;
use primitives::U256;

use crate::InstructionContext;

/// Implements the MLOAD instruction.
///
/// Loads a 32-byte word from memory.
pub fn mload<WIRE: InterpreterTypes, H: Host + ?Sized>(context: InstructionContext<'_, H, WIRE>) {
    popn_top!([], top, context.interpreter);
    let offset = as_usize_or_fail!(context.interpreter, top);
    resize_memory!(context.interpreter, context.host.gas_params(), offset, 32);
    #[cfg(target_os = "zkvm")]
    unsafe {
        let slice = context.interpreter.memory.slice_len(offset, 32);
        let src = slice.as_ref().as_ptr() as *const u32;
        let dst = top as *mut U256 as *mut u32;
        let m1: u32 = 0x00FF_0000;
        // 8-limb byteswap: mem[offset+i*4] (LE u32) → byteswap → dst u32[7-i].
        core::arch::asm!(
            "srli {m2}, {m1}, 8",
            "lw   {x},  0({s})", "slli {t1}, {x}, 24", "srli {r}, {x}, 24", "or {r}, {r}, {t1}",
            "slli {t1}, {x}, 8", "and {t1}, {t1}, {m1}", "or {r}, {r}, {t1}",
            "srli {t1}, {x}, 8", "and {t1}, {t1}, {m2}", "or {r}, {r}, {t1}",
            "sw   {r}, 28({d})",
            "lw   {x},  4({s})", "slli {t1}, {x}, 24", "srli {r}, {x}, 24", "or {r}, {r}, {t1}",
            "slli {t1}, {x}, 8", "and {t1}, {t1}, {m1}", "or {r}, {r}, {t1}",
            "srli {t1}, {x}, 8", "and {t1}, {t1}, {m2}", "or {r}, {r}, {t1}",
            "sw   {r}, 24({d})",
            "lw   {x},  8({s})", "slli {t1}, {x}, 24", "srli {r}, {x}, 24", "or {r}, {r}, {t1}",
            "slli {t1}, {x}, 8", "and {t1}, {t1}, {m1}", "or {r}, {r}, {t1}",
            "srli {t1}, {x}, 8", "and {t1}, {t1}, {m2}", "or {r}, {r}, {t1}",
            "sw   {r}, 20({d})",
            "lw   {x}, 12({s})", "slli {t1}, {x}, 24", "srli {r}, {x}, 24", "or {r}, {r}, {t1}",
            "slli {t1}, {x}, 8", "and {t1}, {t1}, {m1}", "or {r}, {r}, {t1}",
            "srli {t1}, {x}, 8", "and {t1}, {t1}, {m2}", "or {r}, {r}, {t1}",
            "sw   {r}, 16({d})",
            "lw   {x}, 16({s})", "slli {t1}, {x}, 24", "srli {r}, {x}, 24", "or {r}, {r}, {t1}",
            "slli {t1}, {x}, 8", "and {t1}, {t1}, {m1}", "or {r}, {r}, {t1}",
            "srli {t1}, {x}, 8", "and {t1}, {t1}, {m2}", "or {r}, {r}, {t1}",
            "sw   {r}, 12({d})",
            "lw   {x}, 20({s})", "slli {t1}, {x}, 24", "srli {r}, {x}, 24", "or {r}, {r}, {t1}",
            "slli {t1}, {x}, 8", "and {t1}, {t1}, {m1}", "or {r}, {r}, {t1}",
            "srli {t1}, {x}, 8", "and {t1}, {t1}, {m2}", "or {r}, {r}, {t1}",
            "sw   {r},  8({d})",
            "lw   {x}, 24({s})", "slli {t1}, {x}, 24", "srli {r}, {x}, 24", "or {r}, {r}, {t1}",
            "slli {t1}, {x}, 8", "and {t1}, {t1}, {m1}", "or {r}, {r}, {t1}",
            "srli {t1}, {x}, 8", "and {t1}, {t1}, {m2}", "or {r}, {r}, {t1}",
            "sw   {r},  4({d})",
            "lw   {x}, 28({s})", "slli {t1}, {x}, 24", "srli {r}, {x}, 24", "or {r}, {r}, {t1}",
            "slli {t1}, {x}, 8", "and {t1}, {t1}, {m1}", "or {r}, {r}, {t1}",
            "srli {t1}, {x}, 8", "and {t1}, {t1}, {m2}", "or {r}, {r}, {t1}",
            "sw   {r},  0({d})",
            s = in(reg) src,
            d = in(reg) dst,
            m1 = in(reg) m1,
            m2 = out(reg) _,
            x = out(reg) _,
            r = out(reg) _,
            t1 = out(reg) _,
            options(nostack, preserves_flags),
        );
    }
    #[cfg(not(target_os = "zkvm"))]
    {
        *top = U256::try_from_be_slice(
            context.interpreter.memory.slice_len(offset, 32).as_ref(),
        )
        .unwrap();
    }
}

/// Implements the MSTORE instruction.
///
/// Stores a 32-byte word to memory.
pub fn mstore<WIRE: InterpreterTypes, H: Host + ?Sized>(context: InstructionContext<'_, H, WIRE>) {
    popn!([offset, value], context.interpreter);
    let offset = as_usize_or_fail!(context.interpreter, offset);
    resize_memory!(context.interpreter, context.host.gas_params(), offset, 32);
    context
        .interpreter
        .memory
        .set(offset, &value.to_be_bytes::<32>());
}

/// Implements the MSTORE8 instruction.
///
/// Stores a single byte to memory.
pub fn mstore8<WIRE: InterpreterTypes, H: Host + ?Sized>(context: InstructionContext<'_, H, WIRE>) {
    popn!([offset, value], context.interpreter);
    let offset = as_usize_or_fail!(context.interpreter, offset);
    resize_memory!(context.interpreter, context.host.gas_params(), offset, 1);
    context.interpreter.memory.set(offset, &[value.byte(0)]);
}

/// Implements the MSIZE instruction.
///
/// Gets the size of active memory in bytes.
pub fn msize<WIRE: InterpreterTypes, H: ?Sized>(context: InstructionContext<'_, H, WIRE>) {
    push!(
        context.interpreter,
        U256::from(context.interpreter.memory.size())
    );
}

/// Implements the MCOPY instruction.
///
/// EIP-5656: Memory copying instruction that copies memory from one location to another.
pub fn mcopy<WIRE: InterpreterTypes, H: Host + ?Sized>(context: InstructionContext<'_, H, WIRE>) {
    check!(context.interpreter, CANCUN);
    popn!([dst, src, len], context.interpreter);

    // Into usize or fail
    let len = as_usize_or_fail!(context.interpreter, len);
    // Deduce gas
    gas!(
        context.interpreter,
        context.host.gas_params().mcopy_cost(len)
    );

    if len == 0 {
        return;
    }

    let dst = as_usize_or_fail!(context.interpreter, dst);
    let src = as_usize_or_fail!(context.interpreter, src);
    // Resize memory
    resize_memory!(
        context.interpreter,
        context.host.gas_params(),
        max(dst, src),
        len
    );
    // Copy memory in place
    context.interpreter.memory.copy(dst, src, len);
}
