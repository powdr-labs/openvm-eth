use crate::{
    interpreter_types::{Immediates, InterpreterTypes, Jumps, RuntimeFlag, StackTr},
    InstructionResult,
};
use primitives::U256;

use crate::InstructionContext;

/// Implements the POP instruction.
///
/// Removes the top item from the stack.
pub fn pop<WIRE: InterpreterTypes, H: ?Sized>(context: InstructionContext<'_, H, WIRE>) {
    if !context.interpreter.stack.discard_top() {
        context.interpreter.halt_underflow();
    }
}

/// EIP-3855: PUSH0 instruction
///
/// Introduce a new instruction which pushes the constant value 0 onto the stack.
pub fn push0<WIRE: InterpreterTypes, H: ?Sized>(context: InstructionContext<'_, H, WIRE>) {
    check!(context.interpreter, SHANGHAI);
    push!(context.interpreter, U256::ZERO);
}

/// Implements the PUSH1-PUSH32 instructions.
///
/// Pushes N bytes from bytecode onto the stack as a 32-byte value.
pub fn push<const N: usize, WIRE: InterpreterTypes, H: ?Sized>(
    context: InstructionContext<'_, H, WIRE>,
) {
    #[cfg(target_os = "zkvm")]
    {
        if context.interpreter.stack.len() == crate::interpreter::STACK_LIMIT {
            context.interpreter.halt(InstructionResult::StackOverflow);
            return;
        }
        unsafe {
            let src = context.interpreter.bytecode.read_slice(N).as_ptr();
            let dst = context.interpreter.stack.push_uninit_unchecked() as *mut u32;
            // Zero all 32 bytes of dst as 8 u32 LE writes.
            core::ptr::write(dst.add(0), 0);
            core::ptr::write(dst.add(1), 0);
            core::ptr::write(dst.add(2), 0);
            core::ptr::write(dst.add(3), 0);
            core::ptr::write(dst.add(4), 0);
            core::ptr::write(dst.add(5), 0);
            core::ptr::write(dst.add(6), 0);
            core::ptr::write(dst.add(7), 0);
            // Reverse-copy N bytes into the LSB end of the U256. LLVM unrolls
            // the loop because N is const-generic.
            let dst_bytes = dst as *mut u8;
            let mut i = 0;
            while i < N {
                let b = core::ptr::read(src.add(i));
                core::ptr::write(dst_bytes.add(N - 1 - i), b);
                i += 1;
            }
        }
        context.interpreter.bytecode.relative_jump(N as isize);
        return;
    }
    #[cfg(not(target_os = "zkvm"))]
    {
        let slice = context.interpreter.bytecode.read_slice(N);
        if !context.interpreter.stack.push_slice(slice) {
            context.interpreter.halt(InstructionResult::StackOverflow);
            return;
        }

        // Can ignore return. as relative N jump is safe operation
        context.interpreter.bytecode.relative_jump(N as isize);
    }
}

/// Implements the DUP1-DUP16 instructions.
///
/// Duplicates the Nth stack item to the top of the stack.
pub fn dup<const N: usize, WIRE: InterpreterTypes, H: ?Sized>(
    context: InstructionContext<'_, H, WIRE>,
) {
    if !context.interpreter.stack.dup(N) {
        context.interpreter.halt(InstructionResult::StackOverflow);
    }
}

/// Implements the SWAP1-SWAP16 instructions.
///
/// Swaps the top stack item with the Nth stack item.
pub fn swap<const N: usize, WIRE: InterpreterTypes, H: ?Sized>(
    context: InstructionContext<'_, H, WIRE>,
) {
    assert!(N != 0);
    if !context.interpreter.stack.exchange(0, N) {
        context.interpreter.halt(InstructionResult::StackOverflow);
    }
}
