use crate::{
    interpreter::Interpreter,
    interpreter_types::{
        InputsTr, InterpreterTypes, LegacyBytecode, MemoryTr, ReturnData, RuntimeFlag, StackTr,
    },
    CallInput, InstructionResult,
};
use context_interface::{cfg::GasParams, Host};
use core::ptr;
use primitives::{B256, KECCAK_EMPTY, U256};

use crate::InstructionContext;

/// Implements the KECCAK256 instruction.
///
/// Computes Keccak-256 hash of memory data.
pub fn keccak256<WIRE: InterpreterTypes, H: Host + ?Sized>(
    context: InstructionContext<'_, H, WIRE>,
) {
    popn_top!([offset], top, context.interpreter);
    let len = as_usize_or_fail!(context.interpreter, top);
    gas!(
        context.interpreter,
        context.host.gas_params().keccak256_cost(len)
    );
    let hash = if len == 0 {
        KECCAK_EMPTY
    } else {
        let from = as_usize_or_fail!(context.interpreter, offset);
        resize_memory!(context.interpreter, context.host.gas_params(), from, len);
        primitives::keccak256(context.interpreter.memory.slice_len(from, len).as_ref())
    };
    *top = hash.into();
}

/// Implements the ADDRESS instruction.
///
/// Pushes the current contract's address onto the stack.
pub fn address<WIRE: InterpreterTypes, H: ?Sized>(context: InstructionContext<'_, H, WIRE>) {
    push!(
        context.interpreter,
        context
            .interpreter
            .input
            .target_address()
            .into_word()
            .into()
    );
}

/// Implements the CALLER instruction.
///
/// Pushes the caller's address onto the stack.
pub fn caller<WIRE: InterpreterTypes, H: ?Sized>(context: InstructionContext<'_, H, WIRE>) {
    push!(
        context.interpreter,
        context
            .interpreter
            .input
            .caller_address()
            .into_word()
            .into()
    );
}

/// Implements the CODESIZE instruction.
///
/// Pushes the size of running contract's bytecode onto the stack.
pub fn codesize<WIRE: InterpreterTypes, H: ?Sized>(context: InstructionContext<'_, H, WIRE>) {
    push!(
        context.interpreter,
        U256::from(context.interpreter.bytecode.bytecode_len())
    );
}

/// Implements the CODECOPY instruction.
///
/// Copies running contract's bytecode to memory.
pub fn codecopy<WIRE: InterpreterTypes, H: Host + ?Sized>(
    context: InstructionContext<'_, H, WIRE>,
) {
    popn!([memory_offset, code_offset, len], context.interpreter);
    let len = as_usize_or_fail!(context.interpreter, len);
    let Some(memory_offset) = copy_cost_and_memory_resize(
        context.interpreter,
        context.host.gas_params(),
        memory_offset,
        len,
    ) else {
        return;
    };
    let code_offset = as_usize_saturated!(code_offset);

    // Note: This can't panic because we resized memory to fit.
    context.interpreter.memory.set_data(
        memory_offset,
        code_offset,
        len,
        context.interpreter.bytecode.bytecode_slice(),
    );
}

/// Implements the CALLDATALOAD instruction.
///
/// Loads 32 bytes of input data from the specified offset.
pub fn calldataload<WIRE: InterpreterTypes, H: ?Sized>(context: InstructionContext<'_, H, WIRE>) {
    popn_top!([], offset_ptr, context.interpreter);
    let offset = as_usize_saturated!(offset_ptr);

    #[cfg(target_os = "zkvm")]
    {
        // Fast path: full 32 bytes available from CallInput::Bytes. This is
        // the common case (function selector + aligned argument reads). We
        // byteswap directly into the destination U256 via inline asm, same
        // shape as MLOAD.
        if let CallInput::Bytes(bytes) = context.interpreter.input.input() {
            if offset + 32 <= bytes.len() {
                unsafe {
                    let src = bytes.as_ptr().add(offset);
                    let dst = offset_ptr as *mut U256 as *mut u32;
                    let m1: u32 = 0x00FF_0000;
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
                return;
            }
        }
    }

    // Slow path: partial reads, SharedBuffer, or offset beyond input.
    let mut word = B256::ZERO;
    let input = context.interpreter.input.input();
    let input_len = input.len();
    if offset < input_len {
        let count = 32.min(input_len - offset);

        // SAFETY: `count` is bounded by the calldata length.
        match context.interpreter.input.input() {
            CallInput::Bytes(bytes) => {
                unsafe {
                    ptr::copy_nonoverlapping(bytes.as_ptr().add(offset), word.as_mut_ptr(), count)
                };
            }
            CallInput::SharedBuffer(range) => {
                let input_slice = context.interpreter.memory.global_slice(range.clone());
                unsafe {
                    ptr::copy_nonoverlapping(
                        input_slice.as_ptr().add(offset),
                        word.as_mut_ptr(),
                        count,
                    )
                };
            }
        }
    }
    *offset_ptr = word.into();
}

/// Implements the CALLDATASIZE instruction.
///
/// Pushes the size of input data onto the stack.
pub fn calldatasize<WIRE: InterpreterTypes, H: ?Sized>(context: InstructionContext<'_, H, WIRE>) {
    push!(
        context.interpreter,
        U256::from(context.interpreter.input.input().len())
    );
}

/// Implements the CALLVALUE instruction.
///
/// Pushes the value sent with the current call onto the stack.
pub fn callvalue<WIRE: InterpreterTypes, H: ?Sized>(context: InstructionContext<'_, H, WIRE>) {
    push!(context.interpreter, context.interpreter.input.call_value());
}

/// Implements the CALLDATACOPY instruction.
///
/// Copies input data to memory.
pub fn calldatacopy<WIRE: InterpreterTypes, H: Host + ?Sized>(
    context: InstructionContext<'_, H, WIRE>,
) {
    popn!([memory_offset, data_offset, len], context.interpreter);
    let len = as_usize_or_fail!(context.interpreter, len);
    let Some(memory_offset) = copy_cost_and_memory_resize(
        context.interpreter,
        context.host.gas_params(),
        memory_offset,
        len,
    ) else {
        return;
    };

    let data_offset = as_usize_saturated!(data_offset);
    match context.interpreter.input.input() {
        CallInput::Bytes(bytes) => {
            context
                .interpreter
                .memory
                .set_data(memory_offset, data_offset, len, bytes.as_ref());
        }
        CallInput::SharedBuffer(range) => {
            context.interpreter.memory.set_data_from_global(
                memory_offset,
                data_offset,
                len,
                range.clone(),
            );
        }
    }
}

/// EIP-211: New opcodes: RETURNDATASIZE and RETURNDATACOPY
pub fn returndatasize<WIRE: InterpreterTypes, H: ?Sized>(context: InstructionContext<'_, H, WIRE>) {
    check!(context.interpreter, BYZANTIUM);
    push!(
        context.interpreter,
        U256::from(context.interpreter.return_data.buffer().len())
    );
}

/// EIP-211: New opcodes: RETURNDATASIZE and RETURNDATACOPY
pub fn returndatacopy<WIRE: InterpreterTypes, H: Host + ?Sized>(
    context: InstructionContext<'_, H, WIRE>,
) {
    check!(context.interpreter, BYZANTIUM);
    popn!([memory_offset, offset, len], context.interpreter);

    let len = as_usize_or_fail!(context.interpreter, len);
    let data_offset = as_usize_saturated!(offset);

    // Old legacy behavior is to panic if data_end is out of scope of return buffer.
    let data_end = data_offset.saturating_add(len);
    if data_end > context.interpreter.return_data.buffer().len() {
        context.interpreter.halt(InstructionResult::OutOfOffset);
        return;
    }

    let Some(memory_offset) = copy_cost_and_memory_resize(
        context.interpreter,
        context.host.gas_params(),
        memory_offset,
        len,
    ) else {
        return;
    };

    // Note: This can't panic because we resized memory to fit.
    context.interpreter.memory.set_data(
        memory_offset,
        data_offset,
        len,
        context.interpreter.return_data.buffer(),
    );
}

/// Implements the GAS instruction.
///
/// Pushes the amount of remaining gas onto the stack.
pub fn gas<WIRE: InterpreterTypes, H: ?Sized>(context: InstructionContext<'_, H, WIRE>) {
    push!(
        context.interpreter,
        U256::from(context.interpreter.gas.remaining())
    );
}

/// Common logic for copying data from a source buffer to the EVM's memory.
///
/// Handles memory expansion and gas calculation for data copy operations.
pub fn copy_cost_and_memory_resize(
    interpreter: &mut Interpreter<impl InterpreterTypes>,
    gas_params: &GasParams,
    memory_offset: U256,
    len: usize,
) -> Option<usize> {
    // Safe to cast usize to u64
    gas!(interpreter, gas_params.copy_cost(len), None);
    if len == 0 {
        return None;
    }
    let memory_offset = as_usize_or_fail_ret!(interpreter, memory_offset, None);
    resize_memory!(interpreter, gas_params, memory_offset, len, None);

    Some(memory_offset)
}
