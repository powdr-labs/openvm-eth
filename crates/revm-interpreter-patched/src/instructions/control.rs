use crate::{
    interpreter::Interpreter,
    interpreter_types::{InterpreterTypes, Jumps, LoopControl, MemoryTr, RuntimeFlag, StackTr},
    InstructionResult, InterpreterAction,
};
use context_interface::{cfg::GasParams, Host};
use primitives::{Bytes, U256};

use crate::InstructionContext;

/// Implements the JUMP instruction.
///
/// Unconditional jump to a valid destination.
pub fn jump<ITy: InterpreterTypes, H: ?Sized>(context: InstructionContext<'_, H, ITy>) {
    popn!([target], context.interpreter);
    jump_inner(context.interpreter, target);
}

/// Implements the JUMPI instruction.
///
/// Conditional jump to a valid destination if condition is true.
pub fn jumpi<WIRE: InterpreterTypes, H: ?Sized>(context: InstructionContext<'_, H, WIRE>) {
    popn!([target, cond], context.interpreter);
    if !cond.is_zero() {
        jump_inner(context.interpreter, target);
    }
    // openvm: every JUMPI fall-through OR taken-target lands at a new
    // basic-block boundary. Do the AOT lookup here so step() doesn't have
    // to check at every opcode. Skip entirely for contracts with no AOT
    // entries — saves the per-pc table load + zero-check for them.
    #[cfg(feature = "evm-bb-aot")]
    {
        if context.interpreter.bytecode.aot_present() {
            let idx = context.interpreter.bytecode.bb_walker_idx();
            if idx != 0 {
                let entry = &crate::bb_walker_table::BB_WALKER_TABLE[(idx - 1) as usize];
                crate::aot_bb_shapes::dispatch_shape(
                    entry.shape_id,
                    context.interpreter,
                    context.host,
                );
            }
        }
    }
}

/// Internal helper function for jump operations.
///
/// Validates jump target and performs the actual jump.
#[inline(always)]
fn jump_inner<WIRE: InterpreterTypes>(interpreter: &mut Interpreter<WIRE>, target: U256) {
    let target = as_usize_or_fail!(interpreter, target, InstructionResult::InvalidJump);
    if !interpreter.bytecode.is_valid_legacy_jump(target) {
        interpreter.halt(InstructionResult::InvalidJump);
        return;
    }
    // SAFETY: `is_valid_jump` ensures that `dest` is in bounds.
    interpreter.bytecode.absolute_jump(target);
}

/// Implements the JUMPDEST instruction.
///
/// Marks a valid destination for jump operations.
pub fn jumpdest<WIRE: InterpreterTypes, H: ?Sized>(_context: InstructionContext<'_, H, WIRE>) {
    // openvm: JUMPDEST is the canonical BB boundary. step() already advanced
    // pc by 1 (past the JUMPDEST byte) AND debited 1 gas for the JUMPDEST.
    // Rewind pc to the JUMPDEST byte; refund the 1 gas so the BB handler can
    // pre-charge the whole BB's static gas without double-counting.
    // Skip entirely for contracts with no AOT entries.
    #[cfg(feature = "evm-bb-aot")]
    {
        if !_context.interpreter.bytecode.aot_present() {
            return;
        }
        _context.interpreter.bytecode.relative_jump(-1);
        let idx = _context.interpreter.bytecode.bb_walker_idx();
        if idx != 0 {
            _context.interpreter.gas.refund_remaining(1);
            let entry = &crate::bb_walker_table::BB_WALKER_TABLE[(idx - 1) as usize];
            crate::aot_bb_shapes::dispatch_shape(
                entry.shape_id,
                _context.interpreter,
                _context.host,
            );
            return;
        }
        _context.interpreter.bytecode.relative_jump(1);
    }
}

/// Implements the PC instruction.
///
/// Pushes the current program counter onto the stack.
pub fn pc<WIRE: InterpreterTypes, H: ?Sized>(context: InstructionContext<'_, H, WIRE>) {
    // - 1 because we have already advanced the instruction pointer in `Interpreter::step`
    push!(
        context.interpreter,
        U256::from(context.interpreter.bytecode.pc() - 1)
    );
}

#[inline]
/// Internal helper function for return operations.
///
/// Handles memory data retrieval and sets the return action.
fn return_inner(
    interpreter: &mut Interpreter<impl InterpreterTypes>,
    gas_params: &GasParams,
    instruction_result: InstructionResult,
) {
    popn!([offset, len], interpreter);
    let len = as_usize_or_fail!(interpreter, len);
    // Important: Offset must be ignored if len is zeros
    let mut output = Bytes::default();
    if len != 0 {
        let offset = as_usize_or_fail!(interpreter, offset);
        if !interpreter.resize_memory(gas_params, offset, len) {
            return;
        }
        output = interpreter.memory.slice_len(offset, len).to_vec().into()
    }

    interpreter
        .bytecode
        .set_action(InterpreterAction::new_return(
            instruction_result,
            output,
            interpreter.gas,
        ));
}

/// Implements the RETURN instruction.
///
/// Halts execution and returns data from memory.
pub fn ret<WIRE: InterpreterTypes, H: Host + ?Sized>(context: InstructionContext<'_, H, WIRE>) {
    return_inner(
        context.interpreter,
        context.host.gas_params(),
        InstructionResult::Return,
    );
}

/// EIP-140: REVERT instruction
pub fn revert<WIRE: InterpreterTypes, H: Host + ?Sized>(context: InstructionContext<'_, H, WIRE>) {
    check!(context.interpreter, BYZANTIUM);
    return_inner(
        context.interpreter,
        context.host.gas_params(),
        InstructionResult::Revert,
    );
}

/// Stop opcode. This opcode halts the execution.
pub fn stop<WIRE: InterpreterTypes, H: ?Sized>(context: InstructionContext<'_, H, WIRE>) {
    context.interpreter.halt(InstructionResult::Stop);
}

/// Invalid opcode. This opcode halts the execution.
pub fn invalid<WIRE: InterpreterTypes, H: ?Sized>(context: InstructionContext<'_, H, WIRE>) {
    context.interpreter.halt(InstructionResult::InvalidFEOpcode);
}

/// Unknown opcode. This opcode halts the execution.
pub fn unknown<WIRE: InterpreterTypes, H: ?Sized>(context: InstructionContext<'_, H, WIRE>) {
    context.interpreter.halt(InstructionResult::OpcodeNotFound);
}
