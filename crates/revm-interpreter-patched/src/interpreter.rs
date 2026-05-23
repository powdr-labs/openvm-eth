//! Core interpreter implementation and components.

/// Extended bytecode functionality.
pub mod ext_bytecode;
mod input;
mod loop_control;
mod return_data;
mod runtime_flags;
mod shared_memory;
mod stack;

use context_interface::cfg::GasParams;
// re-exports
pub use ext_bytecode::ExtBytecode;
pub use input::InputsImpl;
pub use return_data::ReturnDataImpl;
pub use runtime_flags::RuntimeFlags;
pub use shared_memory::{num_words, resize_memory, SharedMemory};
pub use stack::{Stack, STACK_LIMIT};

// imports
use crate::{
    host::DummyHost, instruction_context::InstructionContext, interpreter_types::*, Gas, Host,
    InstructionResult, InstructionTable, InterpreterAction,
};
use bytecode::Bytecode;
use primitives::{hardfork::SpecId, Bytes};

/// Main interpreter structure that contains all components defined in [`InterpreterTypes`].
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Interpreter<WIRE: InterpreterTypes = EthInterpreter> {
    /// Bytecode being executed.
    pub bytecode: WIRE::Bytecode,
    /// Gas tracking for execution costs.
    pub gas: Gas,
    /// EVM stack for computation.
    pub stack: WIRE::Stack,
    /// Buffer for return data from calls.
    pub return_data: WIRE::ReturnData,
    /// EVM memory for data storage.
    pub memory: WIRE::Memory,
    /// Input data for current execution context.
    pub input: WIRE::Input,
    /// Runtime flags controlling execution behavior.
    pub runtime_flag: WIRE::RuntimeFlag,
    /// Extended functionality and customizations.
    pub extend: WIRE::Extend,
}

impl<EXT: Default> Interpreter<EthInterpreter<EXT>> {
    /// Create new interpreter
    pub fn new(
        memory: SharedMemory,
        bytecode: ExtBytecode,
        input: InputsImpl,
        is_static: bool,
        spec_id: SpecId,
        gas_limit: u64,
    ) -> Self {
        Self::new_inner(
            Stack::new(),
            memory,
            bytecode,
            input,
            is_static,
            spec_id,
            gas_limit,
        )
    }

    /// Create a new interpreter with default extended functionality.
    pub fn default_ext() -> Self {
        Self::do_default(Stack::new(), SharedMemory::new())
    }

    /// Create a new invalid interpreter.
    pub fn invalid() -> Self {
        Self::do_default(Stack::invalid(), SharedMemory::invalid())
    }

    fn do_default(stack: Stack, memory: SharedMemory) -> Self {
        Self::new_inner(
            stack,
            memory,
            ExtBytecode::default(),
            InputsImpl::default(),
            false,
            SpecId::default(),
            u64::MAX,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new_inner(
        stack: Stack,
        memory: SharedMemory,
        bytecode: ExtBytecode,
        input: InputsImpl,
        is_static: bool,
        spec_id: SpecId,
        gas_limit: u64,
    ) -> Self {
        Self {
            bytecode,
            gas: Gas::new(gas_limit),
            stack,
            return_data: Default::default(),
            memory,
            input,
            runtime_flag: RuntimeFlags { is_static, spec_id },
            extend: Default::default(),
        }
    }

    /// Clears and reinitializes the interpreter with new parameters.
    #[allow(clippy::too_many_arguments)]
    #[inline(always)]
    pub fn clear(
        &mut self,
        memory: SharedMemory,
        bytecode: ExtBytecode,
        input: InputsImpl,
        is_static: bool,
        spec_id: SpecId,
        gas_limit: u64,
    ) {
        let Self {
            bytecode: bytecode_ref,
            gas,
            stack,
            return_data,
            memory: memory_ref,
            input: input_ref,
            runtime_flag,
            extend,
        } = self;
        *bytecode_ref = bytecode;
        *gas = Gas::new(gas_limit);
        if stack.data().capacity() == 0 {
            *stack = Stack::new();
        } else {
            stack.clear();
        }
        return_data.0.clear();
        *memory_ref = memory;
        *input_ref = input;
        *runtime_flag = RuntimeFlags { spec_id, is_static };
        *extend = EXT::default();
    }

    /// Sets the bytecode that is going to be executed
    pub fn with_bytecode(mut self, bytecode: Bytecode) -> Self {
        self.bytecode = ExtBytecode::new(bytecode);
        self
    }
}

impl Default for Interpreter<EthInterpreter> {
    fn default() -> Self {
        Self::default_ext()
    }
}

/// Default types for Ethereum interpreter.
#[derive(Debug)]
pub struct EthInterpreter<EXT = (), MG = SharedMemory> {
    _phantom: core::marker::PhantomData<fn() -> (EXT, MG)>,
}

impl<EXT> InterpreterTypes for EthInterpreter<EXT> {
    type Stack = Stack;
    type Memory = SharedMemory;
    type Bytecode = ExtBytecode;
    type ReturnData = ReturnDataImpl;
    type Input = InputsImpl;
    type RuntimeFlag = RuntimeFlags;
    type Extend = EXT;
    type Output = InterpreterAction;
}

impl<IW: InterpreterTypes> Interpreter<IW> {
    /// Performs EVM memory resize.
    #[inline]
    #[must_use]
    pub fn resize_memory(&mut self, gas_params: &GasParams, offset: usize, len: usize) -> bool {
        if let Err(result) = resize_memory(&mut self.gas, &mut self.memory, gas_params, offset, len)
        {
            self.halt(result);
            return false;
        }
        true
    }

    /// Takes the next action from the control and returns it.
    #[inline]
    pub fn take_next_action(&mut self) -> InterpreterAction {
        self.bytecode.reset_action();
        // Return next action if it is some.
        let action = core::mem::take(self.bytecode.action()).expect("Interpreter to set action");
        action
    }

    /// Halt the interpreter with the given result.
    ///
    /// This will set the action to [`InterpreterAction::Return`] and set the gas to the current gas.
    #[cold]
    #[inline(never)]
    pub fn halt(&mut self, result: InstructionResult) {
        self.bytecode
            .set_action(InterpreterAction::new_halt(result, self.gas));
    }

    /// Halt the interpreter with the given result.
    ///
    /// This will set the action to [`InterpreterAction::Return`] and set the gas to the current gas.
    #[cold]
    #[inline(never)]
    pub fn halt_fatal(&mut self) {
        self.bytecode.set_action(InterpreterAction::new_halt(
            InstructionResult::FatalExternalError,
            self.gas,
        ));
    }

    /// Halt the interpreter with an out-of-gas error.
    #[cold]
    #[inline(never)]
    pub fn halt_oog(&mut self) {
        self.gas.spend_all();
        self.halt(InstructionResult::OutOfGas);
    }

    /// Halt the interpreter with an out-of-gas error.
    #[cold]
    #[inline(never)]
    pub fn halt_memory_oog(&mut self) {
        self.halt(InstructionResult::MemoryOOG);
    }

    /// Halt the interpreter with an out-of-gas error.
    #[cold]
    #[inline(never)]
    pub fn halt_memory_limit_oog(&mut self) {
        self.halt(InstructionResult::MemoryLimitOOG);
    }

    /// Halt the interpreter with and overflow error.
    #[cold]
    #[inline(never)]
    pub fn halt_overflow(&mut self) {
        self.halt(InstructionResult::StackOverflow);
    }

    /// Halt the interpreter with and underflow error.
    #[cold]
    #[inline(never)]
    pub fn halt_underflow(&mut self) {
        self.halt(InstructionResult::StackUnderflow);
    }

    /// Halt the interpreter with and not activated error.
    #[cold]
    #[inline(never)]
    pub fn halt_not_activated(&mut self) {
        self.halt(InstructionResult::NotActivated);
    }

    /// Return with the given output.
    ///
    /// This will set the action to [`InterpreterAction::Return`] and set the gas to the current gas.
    pub fn return_with_output(&mut self, output: Bytes) {
        self.bytecode.set_action(InterpreterAction::new_return(
            InstructionResult::Return,
            output,
            self.gas,
        ));
    }

    /// Runtime pattern-match dispatch for known EVM basic blocks. Returns
    /// `true` if the current basic block was handled (either by executing
    /// a transpiled handler or by halting the interpreter), in which case
    /// the caller skips the normal opcode dispatch.
    #[cfg(feature = "evm-jit")]
    #[inline(always)]
    fn try_jit_dispatch(&mut self, opcode: u8) -> bool {
        match opcode {
            // DUP1 PUSH4 SEL EQ PUSH2 TGT JUMPI (11 bytes total).
            0x80 => {
                let tail = self.bytecode.read_slice(11);
                if tail[1] == 0x63          // PUSH4
                    && tail[6] == 0x14      // EQ
                    && tail[7] == 0x61      // PUSH2
                    && tail[10] == 0x57     // JUMPI
                {
                    let sel = u32::from_be_bytes([tail[2], tail[3], tail[4], tail[5]]);
                    let tgt = u16::from_be_bytes([tail[8], tail[9]]);
                    #[cfg(not(target_os = "zkvm"))]
                    {
                        let pc = self.bytecode.pc();
                        let h = self.bytecode.bytecode_hash_bytes();
                        crate::bb_log::record_selector_match(h, pc as u32, sel, tgt);
                    }
                    return self.dispatch_selector(sel, tgt as usize);
                }
                false
            }
            // JUMPDEST SWAP3 SWAP2 POP POP JUMP (6 bytes total).
            0x5B => {
                let tail = self.bytecode.read_slice(6);
                if tail[1] == 0x92          // SWAP3
                    && tail[2] == 0x91      // SWAP2
                    && tail[3] == 0x50      // POP
                    && tail[4] == 0x50      // POP
                    && tail[5] == 0x56      // JUMP
                {
                    #[cfg(not(target_os = "zkvm"))]
                    {
                        let pc = self.bytecode.pc();
                        let h = self.bytecode.bytecode_hash_bytes();
                        crate::bb_log::record_epilogue_match(h, pc as u32);
                    }
                    return self.dispatch_epilogue();
                }
                false
            }
            _ => false,
        }
    }

    /// AOT-table dispatch for known EVM basic blocks. Looks up the current
    /// `(code_hash, pc)` in the precomputed `AOT_TABLE`. Returns `true` if
    /// handled.
    #[cfg(feature = "evm-aot")]
    #[inline(always)]
    fn try_aot_dispatch(&mut self, opcode: u8) -> bool {
        // Sound pre-filter on the set of first-opcodes used by entries in
        // AOT_TABLE. Avoids paying the per-pc table-load + zero-check for
        // the ~90%+ of opcodes that can never match any entry.
        if !matches!(opcode, 0x80 | 0x5B) {
            return false;
        }
        let idx = self.bytecode.aot_table_idx();
        if idx == 0 {
            return false;
        }
        let entry = &crate::aot_table::AOT_TABLE[(idx - 1) as usize];
        match entry.kind {
            crate::aot_table_types::AotKind::SelectorDispatch { selector, target } => {
                self.dispatch_selector(selector, target as usize)
            }
            crate::aot_table_types::AotKind::Epilogue => self.dispatch_epilogue(),
        }
    }

    /// Transpiled handler for `DUP1 PUSH4 SEL EQ PUSH2 TGT JUMPI`. Compares
    /// stack top to `selector` (as a 32-byte LE U256 with high bytes zero)
    /// and jumps to `target` if equal, otherwise advances pc past the
    /// 11-byte block.
    #[cfg(any(feature = "evm-jit", feature = "evm-aot"))]
    #[inline(always)]
    fn dispatch_selector(&mut self, selector: u32, target: usize) -> bool {
        let stack_len = self.stack.len();
        if stack_len < 1 || stack_len + 2 > STACK_LIMIT {
            // Fall back: let the normal opcode pipeline produce the right halt.
            return false;
        }
        // Sum of static gases: DUP1=3, PUSH4=3, EQ=3, PUSH2=3, JUMPI=10 = 22.
        if !self.gas.record_cost(22) {
            self.halt_oog();
            return true;
        }
        let limbs = self.stack.data()[stack_len - 1].as_limbs();
        let hit = limbs[3] == 0
            && limbs[2] == 0
            && limbs[1] == 0
            && limbs[0] == selector as u64;
        if hit {
            if !self.bytecode.is_valid_legacy_jump(target) {
                self.halt(InstructionResult::InvalidJump);
                return true;
            }
            self.bytecode.absolute_jump(target);
        } else {
            self.bytecode.relative_jump(11);
        }
        true
    }

    /// Transpiled handler for `JUMPDEST SWAP3 SWAP2 POP POP JUMP`. Pops 3
    /// stack elements, replaces stack[len-4] with the original top, and
    /// jumps to what was originally stack[len-4] (the return PC).
    #[cfg(any(feature = "evm-jit", feature = "evm-aot"))]
    #[inline(always)]
    fn dispatch_epilogue(&mut self) -> bool {
        let stack_len = self.stack.len();
        if stack_len < 4 {
            // Fall back so the normal pipeline produces the right halt.
            return false;
        }
        // Sum of static gases: JUMPDEST=1, SWAP3=3, SWAP2=3, POP=2, POP=2, JUMP=8 = 19.
        if !self.gas.record_cost(19) {
            self.halt_oog();
            return true;
        }
        // The JUMP target is the U256 at depth 3 from the top — i.e., index
        // (len - 4) in the data slice. Validate it fits in a usize before
        // we touch the stack.
        let target_limbs = self.stack.data()[stack_len - 4].as_limbs();
        if target_limbs[3] != 0
            || target_limbs[2] != 0
            || target_limbs[1] != 0
            || target_limbs[0] > usize::MAX as u64
        {
            self.halt(InstructionResult::InvalidJump);
            return true;
        }
        let target = target_limbs[0] as usize;
        // Replace stack[len-4] with the original top (stack[len-1]) and pop 3.
        unsafe {
            let (_p_top1, p_top) = self.stack.top_pair_ptr_unchecked();
            let stack_base = p_top.sub(stack_len - 1);
            let dst = stack_base.add(stack_len - 4);
            *dst = *p_top;
            self.stack.shrink_unchecked(3);
        }
        if !self.bytecode.is_valid_legacy_jump(target) {
            self.halt(InstructionResult::InvalidJump);
            return true;
        }
        self.bytecode.absolute_jump(target);
        true
    }

    /// Executes the instruction at the current instruction pointer.
    ///
    /// Internally it will increment instruction pointer by one.
    #[inline]
    pub fn step<H: Host + ?Sized>(
        &mut self,
        instruction_table: &InstructionTable<IW, H>,
        host: &mut H,
    ) {
        // Get current opcode.
        let opcode = self.bytecode.opcode();

        crate::bb_log::record(opcode);
        #[cfg(not(target_os = "zkvm"))]
        {
            let __h = self.bytecode.bytecode_hash_bytes();
            crate::bb_log::record_op_count(__h);
        }

        // Transpiled basic-block dispatch (evm-jit / evm-aot). The evm-bb-aot
        // path lives outside step() — it hooks the JUMPDEST + JUMPI opcode
        // handlers and an initial check in `run_plain`, so step() pays zero
        // per-opcode tax for BB dispatch.
        #[cfg(feature = "evm-jit")]
        {
            if self.try_jit_dispatch(opcode) {
                return;
            }
        }
        #[cfg(feature = "evm-aot")]
        {
            if self.try_aot_dispatch(opcode) {
                return;
            }
        }

        // SAFETY: In analysis we are doing padding of bytecode so that we are sure that last
        // byte instruction is STOP so we are safe to just increment program_counter bcs on last instruction
        // it will do noop and just stop execution of this contract
        self.bytecode.relative_jump(1);

        let instruction = unsafe { instruction_table.get_unchecked(opcode as usize) };

        if self.gas.record_cost_unsafe(instruction.static_gas()) {
            return self.halt_oog();
        }
        let context = InstructionContext {
            interpreter: self,
            host,
        };
        instruction.execute(context);
    }

    /// Executes the instruction at the current instruction pointer.
    ///
    /// Internally it will increment instruction pointer by one.
    ///
    /// This uses dummy Host.
    #[inline]
    pub fn step_dummy(&mut self, instruction_table: &InstructionTable<IW, DummyHost>) {
        self.step(instruction_table, &mut DummyHost::default());
    }

    /// Executes the interpreter until it returns or stops.
    #[inline]
    pub fn run_plain<H: Host + ?Sized>(
        &mut self,
        instruction_table: &InstructionTable<IW, H>,
        host: &mut H,
    ) -> InterpreterAction {
        // openvm: frame entry. The first opcode is at pc=0 and may be a BB
        // start in our AOT table. Do one check before the loop so step()
        // doesn't have to do per-opcode boundary detection.
        #[cfg(feature = "evm-bb-aot")]
        {
            if self.bytecode.aot_present() {
                let idx = self.bytecode.bb_walker_idx();
                if idx != 0 {
                    let entry =
                        &crate::bb_walker_table::BB_WALKER_TABLE[(idx - 1) as usize];
                    crate::aot_bb_shapes::dispatch_shape(entry.shape_id, self, host);
                }
            }
        }
        while self.bytecode.is_not_end() {
            self.step(instruction_table, host);
        }
        self.take_next_action()
    }
}

/* used for cargo asm
pub fn asm_step(
    interpreter: &mut Interpreter<EthInterpreter>,
    instruction_table: &InstructionTable<EthInterpreter, DummyHost>,
    host: &mut DummyHost,
) {
    interpreter.step(instruction_table, host);
}

pub fn asm_run(
    interpreter: &mut Interpreter<EthInterpreter>,
    instruction_table: &InstructionTable<EthInterpreter, DummyHost>,
    host: &mut DummyHost,
) {
    interpreter.run_plain(instruction_table, host);
}
*/

/// The result of an interpreter operation.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct InterpreterResult {
    /// The result of the instruction execution.
    pub result: InstructionResult,
    /// The output of the instruction execution.
    pub output: Bytes,
    /// The gas usage information.
    pub gas: Gas,
}

impl InterpreterResult {
    /// Returns a new `InterpreterResult` with the given values.
    pub fn new(result: InstructionResult, output: Bytes, gas: Gas) -> Self {
        Self {
            result,
            output,
            gas,
        }
    }

    /// Returns a new `InterpreterResult` for an out-of-gas error with the given gas limit.
    pub fn new_oog(gas_limit: u64) -> Self {
        Self {
            result: InstructionResult::OutOfGas,
            output: Bytes::default(),
            gas: Gas::new_spent(gas_limit),
        }
    }

    /// Returns whether the instruction result is a success.
    #[inline]
    pub const fn is_ok(&self) -> bool {
        self.result.is_ok()
    }

    /// Returns whether the instruction result is a revert.
    #[inline]
    pub const fn is_revert(&self) -> bool {
        self.result.is_revert()
    }

    /// Returns whether the instruction result is an error.
    #[inline]
    pub const fn is_error(&self) -> bool {
        self.result.is_error()
    }
}

// Special implementation for types where Output can be created from InterpreterAction
impl<IW: InterpreterTypes> Interpreter<IW>
where
    IW::Output: From<InterpreterAction>,
{
    /// Takes the next action from the control and returns it as the specific Output type.
    #[inline]
    pub fn take_next_action_as_output(&mut self) -> IW::Output {
        From::from(self.take_next_action())
    }

    /// Executes the interpreter until it returns or stops, returning the specific Output type.
    #[inline]
    pub fn run_plain_as_output<H: Host + ?Sized>(
        &mut self,
        instruction_table: &InstructionTable<IW, H>,
        host: &mut H,
    ) -> IW::Output {
        From::from(self.run_plain(instruction_table, host))
    }
}

#[cfg(test)]
mod tests {
    #[test]
    #[cfg(feature = "serde")]
    fn test_interpreter_serde() {
        use super::*;
        use bytecode::Bytecode;
        use primitives::Bytes;

        let bytecode = Bytecode::new_raw(Bytes::from(&[0x60, 0x00, 0x60, 0x00, 0x01][..]));
        let interpreter = Interpreter::<EthInterpreter>::new(
            SharedMemory::new(),
            ExtBytecode::new(bytecode),
            InputsImpl::default(),
            false,
            SpecId::default(),
            u64::MAX,
        );

        let serialized = serde_json::to_string_pretty(&interpreter).unwrap();
        let deserialized: Interpreter<EthInterpreter> = serde_json::from_str(&serialized).unwrap();

        assert_eq!(
            interpreter.bytecode.pc(),
            deserialized.bytecode.pc(),
            "Program counter should be preserved"
        );
    }
}

#[test]
fn test_mstore_big_offset_memory_oog() {
    use super::*;
    use crate::{host::DummyHost, instructions::instruction_table};
    use bytecode::Bytecode;
    use primitives::Bytes;

    let code = Bytes::from(
        &[
            0x60, 0x00, // PUSH1 0x00
            0x61, 0x27, 0x10, // PUSH2 0x2710  (10,000)
            0x52, // MSTORE
            0x00, // STOP
        ][..],
    );
    let bytecode = Bytecode::new_raw(code);

    let mut interpreter = Interpreter::<EthInterpreter>::new(
        SharedMemory::new(),
        ExtBytecode::new(bytecode),
        InputsImpl::default(),
        false,
        SpecId::default(),
        1000,
    );

    let table = instruction_table::<EthInterpreter, DummyHost>();
    let mut host = DummyHost::default();
    let action = interpreter.run_plain(&table, &mut host);

    assert!(action.is_return());
    assert_eq!(
        action.instruction_result(),
        Some(InstructionResult::MemoryOOG)
    );
}

#[test]
#[cfg(feature = "memory_limit")]
fn test_mstore_big_offset_memory_limit_oog() {
    use super::*;
    use crate::{host::DummyHost, instructions::instruction_table};
    use bytecode::Bytecode;
    use primitives::Bytes;

    let code = Bytes::from(
        &[
            0x60, 0x00, // PUSH1 0x00
            0x61, 0x27, 0x10, // PUSH2 0x2710  (10,000)
            0x52, // MSTORE
            0x00, // STOP
        ][..],
    );
    let bytecode = Bytecode::new_raw(code);

    let mut interpreter = Interpreter::<EthInterpreter>::new(
        SharedMemory::new_with_memory_limit(1000),
        ExtBytecode::new(bytecode),
        InputsImpl::default(),
        false,
        SpecId::default(),
        100000,
    );

    let table = instruction_table::<EthInterpreter, DummyHost>();
    let mut host = DummyHost::default();
    let action = interpreter.run_plain(&table, &mut host);

    assert!(action.is_return());
    assert_eq!(
        action.instruction_result(),
        Some(InstructionResult::MemoryLimitOOG)
    );
}
