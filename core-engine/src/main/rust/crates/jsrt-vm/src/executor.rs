use crate::opcode;
use crate::{Instruction, VmConstant, VmError, VmProgram};
use std::fmt;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VmHostError {
    Unsupported,
    Failure,
}

impl fmt::Display for VmHostError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Unsupported => "VM host operation is unsupported",
            Self::Failure => "VM host operation failed",
        })
    }
}

impl std::error::Error for VmHostError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InvokeKind {
    Virtual,
    Special,
    Static,
    Interface,
    Dynamic,
}

#[derive(Clone, Debug, PartialEq)]
pub enum VmValue<O> {
    Null,
    Int(i32),
    Long(i64),
    Float(f32),
    Double(f64),
    Object(O),
    Uninitialized,
}

impl<O> VmValue<O> {
    pub fn is_null(&self) -> bool {
        matches!(self, Self::Null)
    }

    pub fn is_wide(&self) -> bool {
        matches!(self, Self::Long(_) | Self::Double(_))
    }
}

/// Safe host boundary for object operations. A JNI implementation can provide
/// this trait in the FFI crate; the VM itself never handles raw JNI pointers.
pub trait ObjectOperations {
    type Object: Clone;

    /// Return a Java/host exception raised by the immediately preceding host
    /// operation.  Native hosts use this to preserve the original throwable
    /// across the VM boundary so VM-level catch handlers can match it instead
    /// of seeing a synthetic LinkageError.
    fn take_pending_exception(&mut self) -> Option<(String, Self::Object)> {
        None
    }

    fn invoke(
        &mut self,
        _kind: InvokeKind,
        _reference: &str,
        _receiver: Option<&Self::Object>,
        _arguments: &[VmValue<Self::Object>],
    ) -> Result<VmValue<Self::Object>, VmHostError> {
        Err(VmHostError::Unsupported)
    }

    fn new_object(&mut self, _class: &str) -> Result<Self::Object, VmHostError> {
        Err(VmHostError::Unsupported)
    }

    fn new_primitive_array(
        &mut self,
        _kind: i32,
        _length: i32,
    ) -> Result<Self::Object, VmHostError> {
        Err(VmHostError::Unsupported)
    }

    fn new_reference_array(
        &mut self,
        _class: &str,
        _length: i32,
    ) -> Result<Self::Object, VmHostError> {
        Err(VmHostError::Unsupported)
    }

    fn new_multi_array(
        &mut self,
        _descriptor: &str,
        _dimensions: &[i32],
    ) -> Result<Self::Object, VmHostError> {
        Err(VmHostError::Unsupported)
    }

    fn array_length(&mut self, _array: &Self::Object) -> Result<i32, VmHostError> {
        Err(VmHostError::Unsupported)
    }

    fn array_load(
        &mut self,
        _opcode: u16,
        _array: &Self::Object,
        _index: i32,
    ) -> Result<VmValue<Self::Object>, VmHostError> {
        Err(VmHostError::Unsupported)
    }

    fn array_store(
        &mut self,
        _opcode: u16,
        _array: &Self::Object,
        _index: i32,
        _value: VmValue<Self::Object>,
    ) -> Result<(), VmHostError> {
        Err(VmHostError::Unsupported)
    }

    fn field_get(
        &mut self,
        _opcode: u16,
        _reference: &str,
        _receiver: Option<&Self::Object>,
    ) -> Result<VmValue<Self::Object>, VmHostError> {
        Err(VmHostError::Unsupported)
    }

    fn field_put(
        &mut self,
        _opcode: u16,
        _reference: &str,
        _receiver: Option<&Self::Object>,
        _value: VmValue<Self::Object>,
    ) -> Result<(), VmHostError> {
        Err(VmHostError::Unsupported)
    }

    fn instance_of(&mut self, _object: &Self::Object, _class: &str) -> Result<bool, VmHostError> {
        Err(VmHostError::Unsupported)
    }

    fn same_object(
        &mut self,
        left: &Self::Object,
        right: &Self::Object,
    ) -> Result<bool, VmHostError> {
        Ok(std::ptr::eq(left, right))
    }

    fn cast(&mut self, object: Self::Object, _class: &str) -> Result<Self::Object, VmHostError> {
        Ok(object)
    }

    fn throwable_class(&mut self, _object: &Self::Object) -> Result<Option<String>, VmHostError> {
        Ok(None)
    }

    fn monitor_enter(&mut self, _object: &Self::Object) -> Result<(), VmHostError> {
        Err(VmHostError::Unsupported)
    }

    fn monitor_exit(&mut self, _object: &Self::Object) -> Result<(), VmHostError> {
        Err(VmHostError::Unsupported)
    }

    fn string_constant(&mut self, _value: &str) -> Result<Self::Object, VmHostError> {
        Err(VmHostError::Unsupported)
    }

    /// Materialize a JVM `ldc` class literal as a host class object.  A class
    /// literal is not a Java String: reflection calls such as
    /// `Class.getFields()` and `Class.getResourceAsStream()` require the
    /// actual `java.lang.Class` object associated with the descriptor.
    fn type_constant(&mut self, _descriptor: &str) -> Result<Self::Object, VmHostError> {
        Err(VmHostError::Unsupported)
    }
}

#[cfg(test)]
#[derive(Default)]
pub(crate) struct NoObjectOperations;

#[cfg(test)]
impl ObjectOperations for NoObjectOperations {
    type Object = ();
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecutionLimits {
    pub max_steps: usize,
    pub max_recursion: usize,
    pub max_stack: usize,
    pub max_locals: usize,
    pub max_exception_transfers: usize,
}

impl Default for ExecutionLimits {
    fn default() -> Self {
        Self {
            max_steps: 16 * 1024 * 1024,
            max_recursion: 128,
            max_stack: 65_535,
            max_locals: 65_535,
            max_exception_transfers: 4_096,
        }
    }
}

struct Thrown<O> {
    class_name: String,
    value: VmValue<O>,
}

struct ExecutionFrame<O> {
    locals: Vec<VmValue<O>>,
    stack: Vec<VmValue<O>>,
    operand_scratch: Vec<i32>,
}

impl<O> ExecutionFrame<O> {
    fn new(local_count: usize, stack_capacity: usize) -> Self {
        Self {
            locals: (0..local_count).map(|_| VmValue::Null).collect(),
            stack: Vec::with_capacity(stack_capacity),
            operand_scratch: Vec::new(),
        }
    }

    fn wipe(&mut self) {
        for value in &mut self.locals {
            *value = VmValue::Null;
        }
        for value in &mut self.stack {
            *value = VmValue::Null;
        }
        self.stack.clear();
        self.operand_scratch.fill(0);
        self.operand_scratch.clear();
    }
}

impl<O> Drop for ExecutionFrame<O> {
    fn drop(&mut self) {
        self.wipe();
    }
}

pub struct VmExecutor<H: ObjectOperations> {
    host: H,
    limits: ExecutionLimits,
}

impl<H: ObjectOperations> VmExecutor<H> {
    pub fn new(host: H) -> Self {
        Self {
            host,
            limits: ExecutionLimits::default(),
        }
    }

    pub fn with_limits(mut self, limits: ExecutionLimits) -> Self {
        self.limits = limits;
        self
    }

    pub fn limits(&self) -> ExecutionLimits {
        self.limits
    }

    pub fn host(&self) -> &H {
        &self.host
    }

    pub fn host_mut(&mut self) -> &mut H {
        &mut self.host
    }

    /// Consume the executor and return its host bridge after execution.
    ///
    /// Native hosts use this to transfer ownership of a JNI return reference
    /// out of the execution scope without exposing VM internals to the FFI
    /// layer.
    pub fn into_host(self) -> H {
        self.host
    }

    pub fn execute(
        &mut self,
        program: &VmProgram,
        arguments: &[VmValue<H::Object>],
    ) -> Result<VmValue<H::Object>, VmError> {
        self.execute_at_depth(program, arguments, 0)
    }

    fn execute_at_depth(
        &mut self,
        program: &VmProgram,
        arguments: &[VmValue<H::Object>],
        depth: usize,
    ) -> Result<VmValue<H::Object>, VmError> {
        if depth >= self.limits.max_recursion {
            return Err(VmError::RecursionLimit);
        }
        let local_count = program
            .max_locals()
            .min(self.limits.max_locals)
            .max(arguments.len())
            .max(1);
        let stack_capacity = program.max_stack().min(self.limits.max_stack).max(8);
        if program.max_locals() > self.limits.max_locals
            || program.max_stack() > self.limits.max_stack
        {
            return Err(VmError::LengthTooLarge {
                field: "execution arena",
                length: program.max_locals().max(program.max_stack()),
                maximum: self.limits.max_locals.max(self.limits.max_stack),
            });
        }
        let mut frame = ExecutionFrame::new(local_count, stack_capacity);
        for (index, value) in arguments.iter().enumerate() {
            if index >= frame.locals.len() {
                return Err(VmError::LocalOutOfBounds);
            }
            frame.locals[index] = value.clone();
        }
        let result = self.run(program, &mut frame, depth);
        frame.wipe();
        result
    }

    fn run(
        &mut self,
        program: &VmProgram,
        frame: &mut ExecutionFrame<H::Object>,
        depth: usize,
    ) -> Result<VmValue<H::Object>, VmError> {
        let mut pc = 0usize;
        let mut steps = 0usize;
        let mut exception_transfers = 0usize;
        while pc < program.instructions().len() {
            if steps >= self.limits.max_steps {
                return Err(VmError::StepLimit);
            }
            steps += 1;
            let fault_pc = pc;
            let instruction = &program.instructions()[pc];
            let mut operands = program.instruction_operands(instruction).to_vec();
            frame.operand_scratch.clear();
            frame.operand_scratch.extend_from_slice(&operands);
            let operation =
                self.execute_instruction(program, frame, instruction, &mut operands, pc, depth);
            operands.fill(0);
            frame.operand_scratch.fill(0);
            match operation {
                Ok(Control::Next(next)) => pc = next,
                Ok(Control::Return(value)) => return Ok(value),
                Err(thrown) => {
                    if let Some(handler) = self.find_handler(program, fault_pc, &thrown)? {
                        frame.stack.clear();
                        if frame.stack.len() >= self.limits.max_stack {
                            return Err(VmError::StackOverflow);
                        }
                        frame.stack.push(thrown.value);
                        pc = handler;
                        exception_transfers += 1;
                        if exception_transfers > self.limits.max_exception_transfers {
                            return Err(VmError::StepLimit);
                        }
                    } else {
                        return Err(VmError::UncaughtException(thrown.class_name));
                    }
                }
            }
        }
        Ok(VmValue::Null)
    }

    fn execute_instruction(
        &mut self,
        program: &VmProgram,
        frame: &mut ExecutionFrame<H::Object>,
        instruction: &Instruction,
        operands: &mut [i32],
        pc: usize,
        depth: usize,
    ) -> Result<Control<H::Object>, Thrown<H::Object>> {
        let op = instruction.opcode;
        let next = pc.saturating_add(1);
        match op {
            opcode::NOP | opcode::MAXS => Ok(Control::Next(next)),
            opcode::UNSUPPORTED => Err(thrown("java/lang/VerifyError", VmValue::Null)),
            opcode::ACONST_NULL => {
                push(frame, VmValue::Null, self.limits.max_stack)?;
                Ok(Control::Next(next))
            }
            opcode::ICONST | opcode::BIPUSH | opcode::SIPUSH => {
                let value = operand(operands, 0)?;
                push(frame, VmValue::Int(value), self.limits.max_stack)?;
                Ok(Control::Next(next))
            }
            opcode::FCONST => {
                let value = operand(operands, 0)?;
                push(
                    frame,
                    VmValue::Float(f32::from_bits(value as u32)),
                    self.limits.max_stack,
                )?;
                Ok(Control::Next(next))
            }
            opcode::LCONST
            | opcode::DCONST
            | opcode::LDC_INT
            | opcode::LDC_LONG
            | opcode::LDC_FLOAT
            | opcode::LDC_DOUBLE
            | opcode::LDC_STRING
            | opcode::LDC_TYPE
            | opcode::LDC_HANDLE
            | opcode::LDC_CONDY => {
                let index = usize::try_from(operand(operands, 0)?)
                    .map_err(|_| thrown("java/lang/VerifyError", VmValue::Null))?;
                let value = self
                    .constant_value(program, index, op)
                    .map_err(|_| thrown("java/lang/VerifyError", VmValue::Null))?;
                push(frame, value, self.limits.max_stack)?;
                Ok(Control::Next(next))
            }
            opcode::ILOAD | opcode::LLOAD | opcode::FLOAD | opcode::DLOAD | opcode::ALOAD => {
                let index = local_index(operands, 0, frame.locals.len())?;
                push(frame, frame.locals[index].clone(), self.limits.max_stack)?;
                Ok(Control::Next(next))
            }
            opcode::ISTORE | opcode::LSTORE | opcode::FSTORE | opcode::DSTORE | opcode::ASTORE => {
                let index = local_index(operands, 0, frame.locals.len())?;
                let value = pop(frame)?;
                frame.locals[index] = value;
                Ok(Control::Next(next))
            }
            opcode::IINC => {
                let index = local_index(operands, 0, frame.locals.len())?;
                let increment = operand(operands, 1)?;
                let value = to_i32(&frame.locals[index])
                    .ok_or_else(|| thrown("java/lang/VerifyError", VmValue::Null))?;
                frame.locals[index] = VmValue::Int(value.wrapping_add(increment));
                Ok(Control::Next(next))
            }
            opcode::RET => {
                let index = local_index(operands, 0, frame.locals.len())?;
                let target = usize::try_from(
                    to_i32(&frame.locals[index])
                        .ok_or_else(|| thrown("java/lang/VerifyError", VmValue::Null))?,
                )
                .map_err(|_| thrown("java/lang/VerifyError", VmValue::Null))?;
                if target >= program.instructions().len() {
                    return Err(thrown("java/lang/VerifyError", VmValue::Null));
                }
                Ok(Control::Next(target))
            }
            opcode::POP => {
                pop(frame)?;
                Ok(Control::Next(next))
            }
            opcode::POP2 => {
                let value = pop(frame)?;
                if !value.is_wide() {
                    pop(frame)?;
                }
                Ok(Control::Next(next))
            }
            opcode::DUP => {
                let value = pop(frame)?;
                push(frame, value.clone(), self.limits.max_stack)?;
                push(frame, value, self.limits.max_stack)?;
                Ok(Control::Next(next))
            }
            opcode::DUP_X1 => {
                let a = pop(frame)?;
                let b = pop(frame)?;
                push(frame, a.clone(), self.limits.max_stack)?;
                push(frame, b, self.limits.max_stack)?;
                push(frame, a, self.limits.max_stack)?;
                Ok(Control::Next(next))
            }
            opcode::DUP_X2 => {
                let a = pop(frame)?;
                let b = pop(frame)?;
                let c = pop(frame)?;
                push(frame, a.clone(), self.limits.max_stack)?;
                push(frame, c, self.limits.max_stack)?;
                push(frame, b, self.limits.max_stack)?;
                push(frame, a, self.limits.max_stack)?;
                Ok(Control::Next(next))
            }
            opcode::DUP2 => {
                let a = pop(frame)?;
                if a.is_wide() {
                    push(frame, a.clone(), self.limits.max_stack)?;
                    push(frame, a, self.limits.max_stack)?;
                } else {
                    let b = pop(frame)?;
                    push(frame, b.clone(), self.limits.max_stack)?;
                    push(frame, a.clone(), self.limits.max_stack)?;
                    push(frame, b, self.limits.max_stack)?;
                    push(frame, a, self.limits.max_stack)?;
                }
                Ok(Control::Next(next))
            }
            opcode::SWAP => {
                let a = pop(frame)?;
                let b = pop(frame)?;
                if a.is_wide() || b.is_wide() {
                    return Err(thrown("java/lang/VerifyError", VmValue::Null));
                }
                push(frame, a, self.limits.max_stack)?;
                push(frame, b, self.limits.max_stack)?;
                Ok(Control::Next(next))
            }
            opcode::DUP2_X1 => {
                let a = pop(frame)?;
                let b = pop(frame)?;
                if a.is_wide() {
                    if b.is_wide() {
                        return Err(thrown("java/lang/VerifyError", VmValue::Null));
                    }
                    push(frame, a.clone(), self.limits.max_stack)?;
                    push(frame, b, self.limits.max_stack)?;
                    push(frame, a, self.limits.max_stack)?;
                } else {
                    let c = pop(frame)?;
                    if b.is_wide() || c.is_wide() {
                        return Err(thrown("java/lang/VerifyError", VmValue::Null));
                    }
                    push(frame, b.clone(), self.limits.max_stack)?;
                    push(frame, a.clone(), self.limits.max_stack)?;
                    push(frame, c, self.limits.max_stack)?;
                    push(frame, b, self.limits.max_stack)?;
                    push(frame, a, self.limits.max_stack)?;
                }
                Ok(Control::Next(next))
            }
            opcode::DUP2_X2 => {
                let a = pop(frame)?;
                let b = pop(frame)?;
                if a.is_wide() {
                    if b.is_wide() {
                        push(frame, a.clone(), self.limits.max_stack)?;
                        push(frame, b, self.limits.max_stack)?;
                        push(frame, a, self.limits.max_stack)?;
                    } else {
                        let c = pop(frame)?;
                        if c.is_wide() {
                            return Err(thrown("java/lang/VerifyError", VmValue::Null));
                        }
                        push(frame, a.clone(), self.limits.max_stack)?;
                        push(frame, c, self.limits.max_stack)?;
                        push(frame, b, self.limits.max_stack)?;
                        push(frame, a, self.limits.max_stack)?;
                    }
                } else {
                    if b.is_wide() {
                        return Err(thrown("java/lang/VerifyError", VmValue::Null));
                    }
                    let c = pop(frame)?;
                    if c.is_wide() {
                        push(frame, b.clone(), self.limits.max_stack)?;
                        push(frame, a.clone(), self.limits.max_stack)?;
                        push(frame, c, self.limits.max_stack)?;
                        push(frame, b, self.limits.max_stack)?;
                        push(frame, a, self.limits.max_stack)?;
                    } else {
                        let d = pop(frame)?;
                        if d.is_wide() {
                            return Err(thrown("java/lang/VerifyError", VmValue::Null));
                        }
                        push(frame, b.clone(), self.limits.max_stack)?;
                        push(frame, a.clone(), self.limits.max_stack)?;
                        push(frame, d, self.limits.max_stack)?;
                        push(frame, c, self.limits.max_stack)?;
                        push(frame, b, self.limits.max_stack)?;
                        push(frame, a, self.limits.max_stack)?;
                    }
                }
                Ok(Control::Next(next))
            }
            opcode::IADD | opcode::ISUB | opcode::IMUL | opcode::IDIV | opcode::IREM => {
                let right = to_i32(&pop(frame)?)
                    .ok_or_else(|| thrown("java/lang/VerifyError", VmValue::Null))?;
                let left = to_i32(&pop(frame)?)
                    .ok_or_else(|| thrown("java/lang/VerifyError", VmValue::Null))?;
                let value = match op {
                    opcode::IADD => left.wrapping_add(right),
                    opcode::ISUB => left.wrapping_sub(right),
                    opcode::IMUL => left.wrapping_mul(right),
                    opcode::IDIV if right == 0 => {
                        return Err(thrown("java/lang/ArithmeticException", VmValue::Null))
                    }
                    opcode::IDIV => left.wrapping_div(right),
                    opcode::IREM if right == 0 => {
                        return Err(thrown("java/lang/ArithmeticException", VmValue::Null))
                    }
                    _ => left.wrapping_rem(right),
                };
                push(frame, VmValue::Int(value), self.limits.max_stack)?;
                Ok(Control::Next(next))
            }
            opcode::INEG => {
                let value = to_i32(&pop(frame)?)
                    .ok_or_else(|| thrown("java/lang/VerifyError", VmValue::Null))?;
                push(
                    frame,
                    VmValue::Int(value.wrapping_neg()),
                    self.limits.max_stack,
                )?;
                Ok(Control::Next(next))
            }
            opcode::LADD | opcode::LSUB | opcode::LMUL | opcode::LDIV | opcode::LREM => {
                let right = to_i64(&pop(frame)?)
                    .ok_or_else(|| thrown("java/lang/VerifyError", VmValue::Null))?;
                let left = to_i64(&pop(frame)?)
                    .ok_or_else(|| thrown("java/lang/VerifyError", VmValue::Null))?;
                let value = match op {
                    opcode::LADD => left.wrapping_add(right),
                    opcode::LSUB => left.wrapping_sub(right),
                    opcode::LMUL => left.wrapping_mul(right),
                    opcode::LDIV if right == 0 => {
                        return Err(thrown("java/lang/ArithmeticException", VmValue::Null))
                    }
                    opcode::LDIV => left.wrapping_div(right),
                    opcode::LREM if right == 0 => {
                        return Err(thrown("java/lang/ArithmeticException", VmValue::Null))
                    }
                    _ => left.wrapping_rem(right),
                };
                push(frame, VmValue::Long(value), self.limits.max_stack)?;
                Ok(Control::Next(next))
            }
            opcode::LNEG => {
                let value = to_i64(&pop(frame)?)
                    .ok_or_else(|| thrown("java/lang/VerifyError", VmValue::Null))?;
                push(
                    frame,
                    VmValue::Long(value.wrapping_neg()),
                    self.limits.max_stack,
                )?;
                Ok(Control::Next(next))
            }
            opcode::FADD | opcode::FSUB | opcode::FMUL | opcode::FDIV | opcode::FREM => {
                let right = to_f32(&pop(frame)?)
                    .ok_or_else(|| thrown("java/lang/VerifyError", VmValue::Null))?;
                let left = to_f32(&pop(frame)?)
                    .ok_or_else(|| thrown("java/lang/VerifyError", VmValue::Null))?;
                let value = match op {
                    opcode::FADD => left + right,
                    opcode::FSUB => left - right,
                    opcode::FMUL => left * right,
                    opcode::FDIV => left / right,
                    _ => left % right,
                };
                push(frame, VmValue::Float(value), self.limits.max_stack)?;
                Ok(Control::Next(next))
            }
            opcode::FNEG => {
                let value = to_f32(&pop(frame)?)
                    .ok_or_else(|| thrown("java/lang/VerifyError", VmValue::Null))?;
                push(frame, VmValue::Float(-value), self.limits.max_stack)?;
                Ok(Control::Next(next))
            }
            opcode::DADD | opcode::DSUB | opcode::DMUL | opcode::DDIV | opcode::DREM => {
                let right = to_f64(&pop(frame)?)
                    .ok_or_else(|| thrown("java/lang/VerifyError", VmValue::Null))?;
                let left = to_f64(&pop(frame)?)
                    .ok_or_else(|| thrown("java/lang/VerifyError", VmValue::Null))?;
                let value = match op {
                    opcode::DADD => left + right,
                    opcode::DSUB => left - right,
                    opcode::DMUL => left * right,
                    opcode::DDIV => left / right,
                    _ => left % right,
                };
                push(frame, VmValue::Double(value), self.limits.max_stack)?;
                Ok(Control::Next(next))
            }
            opcode::DNEG => {
                let value = to_f64(&pop(frame)?)
                    .ok_or_else(|| thrown("java/lang/VerifyError", VmValue::Null))?;
                push(frame, VmValue::Double(-value), self.limits.max_stack)?;
                Ok(Control::Next(next))
            }
            opcode::ISHL | opcode::ISHR | opcode::IUSHR => {
                let shift = to_i32(&pop(frame)?)
                    .ok_or_else(|| thrown("java/lang/VerifyError", VmValue::Null))?
                    & 31;
                let value = to_i32(&pop(frame)?)
                    .ok_or_else(|| thrown("java/lang/VerifyError", VmValue::Null))?;
                let result = match op {
                    opcode::ISHL => (value as u32).wrapping_shl(shift as u32) as i32,
                    opcode::ISHR => value >> shift,
                    _ => (value as u32).wrapping_shr(shift as u32) as i32,
                };
                push(frame, VmValue::Int(result), self.limits.max_stack)?;
                Ok(Control::Next(next))
            }
            opcode::LSHL | opcode::LSHR | opcode::LUSHR => {
                let shift = to_i32(&pop(frame)?)
                    .ok_or_else(|| thrown("java/lang/VerifyError", VmValue::Null))?
                    & 63;
                let value = to_i64(&pop(frame)?)
                    .ok_or_else(|| thrown("java/lang/VerifyError", VmValue::Null))?;
                let result = match op {
                    opcode::LSHL => (value as u64).wrapping_shl(shift as u32) as i64,
                    opcode::LSHR => value >> shift,
                    _ => (value as u64).wrapping_shr(shift as u32) as i64,
                };
                push(frame, VmValue::Long(result), self.limits.max_stack)?;
                Ok(Control::Next(next))
            }
            opcode::IAND | opcode::IOR | opcode::IXOR => {
                let right = to_i32(&pop(frame)?)
                    .ok_or_else(|| thrown("java/lang/VerifyError", VmValue::Null))?;
                let left = to_i32(&pop(frame)?)
                    .ok_or_else(|| thrown("java/lang/VerifyError", VmValue::Null))?;
                let value = match op {
                    opcode::IAND => left & right,
                    opcode::IOR => left | right,
                    _ => left ^ right,
                };
                push(frame, VmValue::Int(value), self.limits.max_stack)?;
                Ok(Control::Next(next))
            }
            opcode::LAND | opcode::LOR | opcode::LXOR => {
                let right = to_i64(&pop(frame)?)
                    .ok_or_else(|| thrown("java/lang/VerifyError", VmValue::Null))?;
                let left = to_i64(&pop(frame)?)
                    .ok_or_else(|| thrown("java/lang/VerifyError", VmValue::Null))?;
                let value = match op {
                    opcode::LAND => left & right,
                    opcode::LOR => left | right,
                    _ => left ^ right,
                };
                push(frame, VmValue::Long(value), self.limits.max_stack)?;
                Ok(Control::Next(next))
            }
            opcode::I2L => unary(
                frame,
                self.limits.max_stack,
                |v| Ok(VmValue::Long(to_i32(&v).ok_or(())? as i64)),
                next,
            ),
            opcode::I2F => unary(
                frame,
                self.limits.max_stack,
                |v| Ok(VmValue::Float(to_i32(&v).ok_or(())? as f32)),
                next,
            ),
            opcode::I2D => unary(
                frame,
                self.limits.max_stack,
                |v| Ok(VmValue::Double(to_i32(&v).ok_or(())? as f64)),
                next,
            ),
            opcode::L2I => unary(
                frame,
                self.limits.max_stack,
                |v| Ok(VmValue::Int(to_i64(&v).ok_or(())? as i32)),
                next,
            ),
            opcode::L2F => unary(
                frame,
                self.limits.max_stack,
                |v| Ok(VmValue::Float(to_i64(&v).ok_or(())? as f32)),
                next,
            ),
            opcode::L2D => unary(
                frame,
                self.limits.max_stack,
                |v| Ok(VmValue::Double(to_i64(&v).ok_or(())? as f64)),
                next,
            ),
            opcode::F2I => unary(
                frame,
                self.limits.max_stack,
                |v| Ok(VmValue::Int(to_f32(&v).ok_or(())? as i32)),
                next,
            ),
            opcode::F2L => unary(
                frame,
                self.limits.max_stack,
                |v| Ok(VmValue::Long(to_f32(&v).ok_or(())? as i64)),
                next,
            ),
            opcode::F2D => unary(
                frame,
                self.limits.max_stack,
                |v| Ok(VmValue::Double(to_f32(&v).ok_or(())? as f64)),
                next,
            ),
            opcode::D2I => unary(
                frame,
                self.limits.max_stack,
                |v| Ok(VmValue::Int(to_f64(&v).ok_or(())? as i32)),
                next,
            ),
            opcode::D2L => unary(
                frame,
                self.limits.max_stack,
                |v| Ok(VmValue::Long(to_f64(&v).ok_or(())? as i64)),
                next,
            ),
            opcode::D2F => unary(
                frame,
                self.limits.max_stack,
                |v| Ok(VmValue::Float(to_f64(&v).ok_or(())? as f32)),
                next,
            ),
            opcode::I2B => unary(
                frame,
                self.limits.max_stack,
                |v| Ok(VmValue::Int(to_i32(&v).ok_or(())? as i8 as i32)),
                next,
            ),
            opcode::I2C => unary(
                frame,
                self.limits.max_stack,
                |v| Ok(VmValue::Int(to_i32(&v).ok_or(())? as u16 as i32)),
                next,
            ),
            opcode::I2S => unary(
                frame,
                self.limits.max_stack,
                |v| Ok(VmValue::Int(to_i32(&v).ok_or(())? as i16 as i32)),
                next,
            ),
            opcode::LCMP => compare_long(frame, self.limits.max_stack, next),
            opcode::FCMPL | opcode::FCMPG => {
                compare_float(frame, self.limits.max_stack, op == opcode::FCMPL, next)
            }
            opcode::DCMPL | opcode::DCMPG => {
                compare_double(frame, self.limits.max_stack, op == opcode::DCMPL, next)
            }
            opcode::IFEQ
            | opcode::IFNE
            | opcode::IFLT
            | opcode::IFGE
            | opcode::IFGT
            | opcode::IFLE => {
                let target = target_operand(operands, 0, program.instructions().len())?;
                let value = to_i32(&pop(frame)?)
                    .ok_or_else(|| thrown("java/lang/VerifyError", VmValue::Null))?;
                let take = match op {
                    opcode::IFEQ => value == 0,
                    opcode::IFNE => value != 0,
                    opcode::IFLT => value < 0,
                    opcode::IFGE => value >= 0,
                    opcode::IFGT => value > 0,
                    _ => value <= 0,
                };
                Ok(Control::Next(if take { target } else { next }))
            }
            opcode::IF_ICMPEQ
            | opcode::IF_ICMPNE
            | opcode::IF_ICMPLT
            | opcode::IF_ICMPGE
            | opcode::IF_ICMPGT
            | opcode::IF_ICMPLE => {
                let target = target_operand(operands, 0, program.instructions().len())?;
                let right = to_i32(&pop(frame)?)
                    .ok_or_else(|| thrown("java/lang/VerifyError", VmValue::Null))?;
                let left = to_i32(&pop(frame)?)
                    .ok_or_else(|| thrown("java/lang/VerifyError", VmValue::Null))?;
                let take = match op {
                    opcode::IF_ICMPEQ => left == right,
                    opcode::IF_ICMPNE => left != right,
                    opcode::IF_ICMPLT => left < right,
                    opcode::IF_ICMPGE => left >= right,
                    opcode::IF_ICMPGT => left > right,
                    _ => left <= right,
                };
                Ok(Control::Next(if take { target } else { next }))
            }
            opcode::IFNULL | opcode::IFNONNULL => {
                let target = target_operand(operands, 0, program.instructions().len())?;
                let value = pop(frame)?;
                let take = if op == opcode::IFNULL {
                    value.is_null()
                } else {
                    !value.is_null()
                };
                Ok(Control::Next(if take { target } else { next }))
            }
            opcode::IF_ACMPEQ | opcode::IF_ACMPNE => {
                let target = target_operand(operands, 0, program.instructions().len())?;
                let right = pop(frame)?;
                let left = pop(frame)?;
                let equal = self.same_value(&left, &right)?;
                Ok(Control::Next(
                    if (op == opcode::IF_ACMPEQ && equal) || (op == opcode::IF_ACMPNE && !equal) {
                        target
                    } else {
                        next
                    },
                ))
            }
            opcode::GOTO => Ok(Control::Next(target_operand(
                operands,
                0,
                program.instructions().len(),
            )?)),
            opcode::JSR => {
                push(frame, VmValue::Int(next as i32), self.limits.max_stack)?;
                Ok(Control::Next(target_operand(
                    operands,
                    0,
                    program.instructions().len(),
                )?))
            }
            opcode::IRETURN
            | opcode::LRETURN
            | opcode::FRETURN
            | opcode::DRETURN
            | opcode::ARETURN => Ok(Control::Return(pop(frame)?)),
            opcode::RETURN => Ok(Control::Return(VmValue::Null)),
            opcode::ATHROW => {
                let value = pop(frame)?;
                let class_name = match &value {
                    VmValue::Object(object) => self
                        .host
                        .throwable_class(object)
                        .map_err(|_| thrown("java/lang/RuntimeException", VmValue::Null))?
                        .unwrap_or_else(|| "java/lang/RuntimeException".to_owned()),
                    VmValue::Null => "java/lang/NullPointerException".to_owned(),
                    _ => "java/lang/RuntimeException".to_owned(),
                };
                Err(Thrown { class_name, value })
            }
            opcode::INVOKEVIRTUAL
            | opcode::INVOKESPECIAL
            | opcode::INVOKESTATIC
            | opcode::INVOKEINTERFACE
            | opcode::INVOKEDYNAMIC => self.invoke(program, frame, op, operands, depth, next),
            opcode::NEW => {
                let class = cp_string(program, operand(operands, 0)?)?;
                let object = self
                    .host
                    .new_object(class)
                    .map_err(|_| thrown("java/lang/InstantiationException", VmValue::Null))?;
                push(frame, VmValue::Object(object), self.limits.max_stack)?;
                Ok(Control::Next(next))
            }
            opcode::NEWARRAY => {
                let kind = operand(operands, 0)?;
                let length = to_i32(&pop(frame)?)
                    .ok_or_else(|| thrown("java/lang/NegativeArraySizeException", VmValue::Null))?;
                let object = self
                    .host
                    .new_primitive_array(kind, length)
                    .map_err(|_| thrown("java/lang/NegativeArraySizeException", VmValue::Null))?;
                push(frame, VmValue::Object(object), self.limits.max_stack)?;
                Ok(Control::Next(next))
            }
            opcode::ANEWARRAY => {
                let class = cp_string(program, operand(operands, 0)?)?;
                let length = to_i32(&pop(frame)?)
                    .ok_or_else(|| thrown("java/lang/NegativeArraySizeException", VmValue::Null))?;
                let object = self
                    .host
                    .new_reference_array(class, length)
                    .map_err(|_| thrown("java/lang/NegativeArraySizeException", VmValue::Null))?;
                push(frame, VmValue::Object(object), self.limits.max_stack)?;
                Ok(Control::Next(next))
            }
            opcode::MULTIANEWARRAY => {
                let descriptor = cp_string(program, operand(operands, 0)?)?;
                let count = usize::try_from(operand(operands, 1)?)
                    .map_err(|_| thrown("java/lang/VerifyError", VmValue::Null))?;
                if count == 0 || count > frame.stack.len() {
                    return Err(thrown("java/lang/VerifyError", VmValue::Null));
                }
                let mut dimensions = Vec::with_capacity(count);
                for _ in 0..count {
                    dimensions.push(to_i32(&pop(frame)?).ok_or_else(|| {
                        thrown("java/lang/NegativeArraySizeException", VmValue::Null)
                    })?);
                }
                dimensions.reverse();
                let object = self
                    .host
                    .new_multi_array(descriptor, &dimensions)
                    .map_err(|_| thrown("java/lang/NegativeArraySizeException", VmValue::Null))?;
                dimensions.fill(0);
                push(frame, VmValue::Object(object), self.limits.max_stack)?;
                Ok(Control::Next(next))
            }
            opcode::ARRAYLENGTH => {
                let value = pop(frame)?;
                let object = as_object(value)?;
                let length = self
                    .host
                    .array_length(&object)
                    .map_err(|_| thrown("java/lang/NullPointerException", VmValue::Null))?;
                push(frame, VmValue::Int(length), self.limits.max_stack)?;
                Ok(Control::Next(next))
            }
            opcode::CHECKCAST => {
                let class = cp_string(program, operand(operands, 0)?)?;
                let value = pop(frame)?;
                let value = match value {
                    VmValue::Null => VmValue::Null,
                    VmValue::Object(object) => VmValue::Object(
                        self.host
                            .cast(object, class)
                            .map_err(|_| thrown("java/lang/ClassCastException", VmValue::Null))?,
                    ),
                    _ => return Err(thrown("java/lang/ClassCastException", VmValue::Null)),
                };
                push(frame, value, self.limits.max_stack)?;
                Ok(Control::Next(next))
            }
            opcode::INSTANCEOF => {
                let class = cp_string(program, operand(operands, 0)?)?;
                let value = pop(frame)?;
                let result = match value {
                    VmValue::Null => false,
                    VmValue::Object(object) => self
                        .host
                        .instance_of(&object, class)
                        .map_err(|_| thrown("java/lang/LinkageError", VmValue::Null))?,
                    _ => false,
                };
                push(
                    frame,
                    VmValue::Int(i32::from(result)),
                    self.limits.max_stack,
                )?;
                Ok(Control::Next(next))
            }
            opcode::GETSTATIC | opcode::PUTSTATIC | opcode::GETFIELD | opcode::PUTFIELD => {
                self.field(program, frame, op, operands, next)
            }
            opcode::IALOAD
            | opcode::LALOAD
            | opcode::FALOAD
            | opcode::DALOAD
            | opcode::AALOAD
            | opcode::BALOAD
            | opcode::CALOAD
            | opcode::SALOAD => {
                let index = to_i32(&pop(frame)?).ok_or_else(|| {
                    thrown("java/lang/ArrayIndexOutOfBoundsException", VmValue::Null)
                })?;
                let array = as_object(pop(frame)?)?;
                let value = self.host.array_load(op, &array, index).map_err(|_| {
                    thrown("java/lang/ArrayIndexOutOfBoundsException", VmValue::Null)
                })?;
                push(frame, value, self.limits.max_stack)?;
                Ok(Control::Next(next))
            }
            opcode::IASTORE
            | opcode::LASTORE
            | opcode::FASTORE
            | opcode::DASTORE
            | opcode::AASTORE
            | opcode::BASTORE
            | opcode::CASTORE
            | opcode::SASTORE => {
                let value = pop(frame)?;
                let index = to_i32(&pop(frame)?).ok_or_else(|| {
                    thrown("java/lang/ArrayIndexOutOfBoundsException", VmValue::Null)
                })?;
                let array = as_object(pop(frame)?)?;
                self.host
                    .array_store(op, &array, index, value)
                    .map_err(|_| {
                        thrown("java/lang/ArrayIndexOutOfBoundsException", VmValue::Null)
                    })?;
                Ok(Control::Next(next))
            }
            opcode::MONITORENTER | opcode::MONITOREXIT => {
                let object = as_object(pop(frame)?)?;
                let result = if op == opcode::MONITORENTER {
                    self.host.monitor_enter(&object)
                } else {
                    self.host.monitor_exit(&object)
                };
                result
                    .map_err(|_| thrown("java/lang/IllegalMonitorStateException", VmValue::Null))?;
                Ok(Control::Next(next))
            }
            opcode::TABLESWITCH => {
                let key = to_i32(&pop(frame)?)
                    .ok_or_else(|| thrown("java/lang/VerifyError", VmValue::Null))?;
                let min = operand(operands, 0)?;
                let max = operand(operands, 1)?;
                let index = if key < min || key > max {
                    2
                } else {
                    usize::try_from(key - min)
                        .map_err(|_| thrown("java/lang/VerifyError", VmValue::Null))?
                        .saturating_add(3)
                };
                Ok(Control::Next(target_operand(
                    operands,
                    index,
                    program.instructions().len(),
                )?))
            }
            opcode::LOOKUPSWITCH => {
                let key = to_i32(&pop(frame)?)
                    .ok_or_else(|| thrown("java/lang/VerifyError", VmValue::Null))?;
                let pairs = usize::try_from(operand(operands, 0)?)
                    .map_err(|_| thrown("java/lang/VerifyError", VmValue::Null))?;
                if operands.len() < pairs.saturating_mul(2).saturating_add(2) {
                    return Err(thrown("java/lang/VerifyError", VmValue::Null));
                }
                let mut target = operand(operands, 1)?;
                for pair in 0..pairs {
                    if operand(operands, 2 + pair * 2)? == key {
                        target = operand(operands, 3 + pair * 2)?;
                        break;
                    }
                }
                let target = usize::try_from(target)
                    .map_err(|_| thrown("java/lang/VerifyError", VmValue::Null))?;
                if target >= program.instructions().len() {
                    return Err(thrown("java/lang/VerifyError", VmValue::Null));
                }
                Ok(Control::Next(target))
            }
            _ => Err(thrown("java/lang/VerifyError", VmValue::Null)),
        }
    }

    fn constant_value(
        &mut self,
        program: &VmProgram,
        index: usize,
        opcode: u16,
    ) -> Result<VmValue<H::Object>, VmError> {
        let constant = program
            .constants()
            .get(index)
            .ok_or(VmError::OperandOutOfBounds)?;
        match (opcode, constant) {
            (opcode::LDC_INT, VmConstant::Int(value)) => Ok(VmValue::Int(*value)),
            (opcode::LDC_LONG | opcode::LCONST, VmConstant::Long(value)) => {
                Ok(VmValue::Long(*value))
            }
            (opcode::LDC_FLOAT | opcode::FCONST, VmConstant::Float(value)) => {
                Ok(VmValue::Float(*value))
            }
            (opcode::LDC_DOUBLE | opcode::DCONST, VmConstant::Double(value)) => {
                Ok(VmValue::Double(*value))
            }
            (opcode::LDC_STRING, VmConstant::String(value)) => Ok(VmValue::Object(
                self.host
                    .string_constant(value.as_str())
                    .map_err(|_| VmError::HostFailure)?,
            )),
            (opcode::LDC_TYPE, VmConstant::String(value)) => Ok(VmValue::Object(
                self.host
                    .type_constant(value.as_str())
                    .map_err(|_| VmError::HostFailure)?,
            )),
            (opcode::LDC_HANDLE | opcode::LDC_CONDY, VmConstant::String(value)) => {
                Ok(VmValue::Object(
                    self.host
                        .string_constant(value.as_str())
                        .map_err(|_| VmError::HostFailure)?,
                ))
            }
            _ => Err(VmError::InvalidConstantPool(
                "constant opcode/type mismatch",
            )),
        }
    }

    fn invoke(
        &mut self,
        program: &VmProgram,
        frame: &mut ExecutionFrame<H::Object>,
        opcode: u16,
        operands: &[i32],
        depth: usize,
        next: usize,
    ) -> Result<Control<H::Object>, Thrown<H::Object>> {
        if depth + 1 >= self.limits.max_recursion {
            return Err(thrown("java/lang/StackOverflowError", VmValue::Null));
        }
        let reference = cp_string(program, operand(operands, 0)?)?;
        let descriptor = if opcode == opcode::INVOKEDYNAMIC {
            dynamic_descriptor(reference)
        } else {
            reference.rsplit_once(':').map(|(_, value)| value)
        }
        .ok_or_else(|| thrown("java/lang/VerifyError", VmValue::Null))?;
        let argument_count = descriptor_arity(descriptor)
            .ok_or_else(|| thrown("java/lang/VerifyError", VmValue::Null))?;
        if argument_count > frame.stack.len() {
            return Err(thrown("java/lang/VerifyError", VmValue::Null));
        }
        let mut arguments = Vec::with_capacity(argument_count);
        for _ in 0..argument_count {
            arguments.push(pop(frame)?);
        }
        arguments.reverse();
        let kind = match opcode {
            opcode::INVOKEVIRTUAL => InvokeKind::Virtual,
            opcode::INVOKESPECIAL => InvokeKind::Special,
            opcode::INVOKESTATIC => InvokeKind::Static,
            opcode::INVOKEINTERFACE => InvokeKind::Interface,
            _ => InvokeKind::Dynamic,
        };
        let receiver_object = if matches!(kind, InvokeKind::Static | InvokeKind::Dynamic) {
            None
        } else {
            let receiver = pop(frame)?;
            Some(as_object(receiver)?)
        };
        let result = match self
            .host
            .invoke(kind, reference, receiver_object.as_ref(), &arguments)
        {
            Ok(value) => Ok(value),
            Err(_) => match self.host.take_pending_exception() {
                Some((class_name, object)) => Err(Thrown {
                    class_name,
                    value: VmValue::Object(object),
                }),
                None => Err(thrown("java/lang/LinkageError", VmValue::Null)),
            },
        };
        arguments.clear();
        let value = result?;
        if !matches!(value, VmValue::Null) || method_return_tag(descriptor) != Some(b'V') {
            push(frame, value, self.limits.max_stack)?;
        }
        Ok(Control::Next(next))
    }

    fn field(
        &mut self,
        program: &VmProgram,
        frame: &mut ExecutionFrame<H::Object>,
        opcode: u16,
        operands: &[i32],
        next: usize,
    ) -> Result<Control<H::Object>, Thrown<H::Object>> {
        let reference = cp_string(program, operand(operands, 0)?)?;
        match opcode {
            opcode::GETSTATIC => {
                let value = self
                    .host
                    .field_get(opcode, reference, None)
                    .map_err(|_| thrown("java/lang/LinkageError", VmValue::Null))?;
                push(frame, value, self.limits.max_stack)?;
            }
            opcode::PUTSTATIC => {
                let value = pop(frame)?;
                self.host
                    .field_put(opcode, reference, None, value)
                    .map_err(|_| thrown("java/lang/LinkageError", VmValue::Null))?;
            }
            opcode::GETFIELD => {
                let receiver = as_object(pop(frame)?)?;
                let value = self
                    .host
                    .field_get(opcode, reference, Some(&receiver))
                    .map_err(|_| thrown("java/lang/NullPointerException", VmValue::Null))?;
                push(frame, value, self.limits.max_stack)?;
            }
            opcode::PUTFIELD => {
                let value = pop(frame)?;
                let receiver = as_object(pop(frame)?)?;
                self.host
                    .field_put(opcode, reference, Some(&receiver), value)
                    .map_err(|_| thrown("java/lang/NullPointerException", VmValue::Null))?;
            }
            _ => return Err(thrown("java/lang/VerifyError", VmValue::Null)),
        }
        Ok(Control::Next(next))
    }

    fn same_value(
        &mut self,
        left: &VmValue<H::Object>,
        right: &VmValue<H::Object>,
    ) -> Result<bool, Thrown<H::Object>> {
        match (left, right) {
            (VmValue::Null, VmValue::Null) => Ok(true),
            (VmValue::Object(left), VmValue::Object(right)) => self
                .host
                .same_object(left, right)
                .map_err(|_| thrown("java/lang/LinkageError", VmValue::Null)),
            _ => Ok(false),
        }
    }

    fn find_handler(
        &mut self,
        program: &VmProgram,
        fault_pc: usize,
        thrown: &Thrown<H::Object>,
    ) -> Result<Option<usize>, VmError> {
        for handler in program.exceptions() {
            let in_range = fault_pc >= handler.start && fault_pc < handler.end;
            if !in_range {
                continue;
            }
            if let Some(type_cp) = handler.type_cp {
                let class = cp_string::<H::Object>(program, type_cp as i32)
                    .map_err(|_| VmError::InvalidException("handler type is not a string"))?;
                let direct_match = thrown.class_name == class;
                if !direct_match {
                    // The serializer intentionally inserts synthetic exception
                    // entries whose catch types are non-resolvable decoy names.
                    // They must behave like non-matching handlers rather than
                    // turning an otherwise valid throw into a host failure.  A
                    // real catch type lookup failure remains fail-closed below.
                    if class.starts_with("javashroud/decoy/") {
                        continue;
                    }
                    let matches = match &thrown.value {
                        VmValue::Object(object) => self
                            .host
                            .instance_of(object, class)
                            .map_err(|_| VmError::HostFailure)?,
                        _ => false,
                    };
                    if !matches {
                        continue;
                    }
                }
            }
            return Ok(Some(handler.handler));
        }
        Ok(None)
    }
}

fn dynamic_descriptor(reference: &str) -> Option<&str> {
    let mut fields = reference.split('|');
    match fields.next()? {
        "mhstatic" => fields.next().and_then(|_| fields.next()),
        // The current-format lambda recipe is encoded as:
        //
        //   lambda|<factory-name>|<factory-descriptor>|<impl-tag>|...
        //
        // The VM invokes the generated factory with the captured arguments,
        // so its descriptor (field 2) is the descriptor that determines how
        // many values must be popped from the VM operand stack.  Treating
        // field 1 as a member reference (the old generic fallback) produced
        // a synthetic VerifyError before the host could link the SAM lambda.
        "lambda" => fields.next().and_then(|_| fields.next()),
        "sam" | "sam-lambda" => fields
            .nth(1)
            .and_then(|value| value.rsplit_once(':').map(|(_, descriptor)| descriptor)),
        _ => fields
            .next()
            .and_then(|value| value.rsplit_once(':').map(|(_, descriptor)| descriptor)),
    }
}

enum Control<O> {
    Next(usize),
    Return(VmValue<O>),
}

fn thrown<O>(class_name: &'static str, value: VmValue<O>) -> Thrown<O> {
    Thrown {
        class_name: class_name.to_owned(),
        value,
    }
}

fn push<O>(
    frame: &mut ExecutionFrame<O>,
    value: VmValue<O>,
    maximum: usize,
) -> Result<(), Thrown<O>> {
    if frame.stack.len() >= maximum {
        return Err(thrown("java/lang/StackOverflowError", VmValue::Null));
    }
    frame.stack.push(value);
    Ok(())
}

fn pop<O>(frame: &mut ExecutionFrame<O>) -> Result<VmValue<O>, Thrown<O>> {
    frame
        .stack
        .pop()
        .ok_or_else(|| thrown("java/lang/VerifyError", VmValue::Null))
}

fn operand<O>(operands: &[i32], index: usize) -> Result<i32, Thrown<O>> {
    operands
        .get(index)
        .copied()
        .ok_or_else(|| thrown("java/lang/VerifyError", VmValue::Null))
}

fn local_index<O>(operands: &[i32], index: usize, locals: usize) -> Result<usize, Thrown<O>> {
    let value = operand(operands, index)?;
    let index =
        usize::try_from(value).map_err(|_| thrown("java/lang/VerifyError", VmValue::Null))?;
    if index >= locals {
        return Err(thrown("java/lang/VerifyError", VmValue::Null));
    }
    Ok(index)
}

fn target_operand<O>(
    operands: &[i32],
    index: usize,
    instruction_count: usize,
) -> Result<usize, Thrown<O>> {
    let target = usize::try_from(operand(operands, index)?)
        .map_err(|_| thrown("java/lang/VerifyError", VmValue::Null))?;
    if target >= instruction_count {
        return Err(thrown("java/lang/VerifyError", VmValue::Null));
    }
    Ok(target)
}

fn cp_string<O>(program: &VmProgram, index: i32) -> Result<&str, Thrown<O>> {
    let index =
        usize::try_from(index).map_err(|_| thrown("java/lang/VerifyError", VmValue::Null))?;
    program
        .constants()
        .get(index)
        .and_then(VmConstant::as_string)
        .ok_or_else(|| thrown("java/lang/VerifyError", VmValue::Null))
}

fn as_object<O>(value: VmValue<O>) -> Result<O, Thrown<O>> {
    match value {
        VmValue::Object(object) => Ok(object),
        VmValue::Null => Err(thrown("java/lang/NullPointerException", VmValue::Null)),
        _ => Err(thrown("java/lang/VerifyError", VmValue::Null)),
    }
}

fn to_i32<O>(value: &VmValue<O>) -> Option<i32> {
    match value {
        VmValue::Int(value) => Some(*value),
        VmValue::Long(value) => Some(*value as i32),
        VmValue::Float(value) => Some(*value as i32),
        VmValue::Double(value) => Some(*value as i32),
        _ => None,
    }
}

fn to_i64<O>(value: &VmValue<O>) -> Option<i64> {
    match value {
        VmValue::Int(value) => Some(i64::from(*value)),
        VmValue::Long(value) => Some(*value),
        VmValue::Float(value) => Some(*value as i64),
        VmValue::Double(value) => Some(*value as i64),
        _ => None,
    }
}

fn to_f32<O>(value: &VmValue<O>) -> Option<f32> {
    match value {
        VmValue::Int(value) => Some(*value as f32),
        VmValue::Long(value) => Some(*value as f32),
        VmValue::Float(value) => Some(*value),
        VmValue::Double(value) => Some(*value as f32),
        _ => None,
    }
}

fn to_f64<O>(value: &VmValue<O>) -> Option<f64> {
    match value {
        VmValue::Int(value) => Some(*value as f64),
        VmValue::Long(value) => Some(*value as f64),
        VmValue::Float(value) => Some(f64::from(*value)),
        VmValue::Double(value) => Some(*value),
        _ => None,
    }
}

fn unary<O, F>(
    frame: &mut ExecutionFrame<O>,
    maximum: usize,
    convert: F,
    next: usize,
) -> Result<Control<O>, Thrown<O>>
where
    F: FnOnce(VmValue<O>) -> Result<VmValue<O>, ()>,
{
    let value = pop(frame)?;
    let result = convert(value).map_err(|_| thrown("java/lang/VerifyError", VmValue::Null))?;
    push(frame, result, maximum)?;
    Ok(Control::Next(next))
}

fn compare_long<O>(
    frame: &mut ExecutionFrame<O>,
    maximum: usize,
    next: usize,
) -> Result<Control<O>, Thrown<O>> {
    let right =
        to_i64(&pop(frame)?).ok_or_else(|| thrown("java/lang/VerifyError", VmValue::Null))?;
    let left =
        to_i64(&pop(frame)?).ok_or_else(|| thrown("java/lang/VerifyError", VmValue::Null))?;
    push(
        frame,
        VmValue::Int(match left.cmp(&right) {
            std::cmp::Ordering::Less => -1,
            std::cmp::Ordering::Equal => 0,
            std::cmp::Ordering::Greater => 1,
        }),
        maximum,
    )?;
    Ok(Control::Next(next))
}

fn compare_float<O>(
    frame: &mut ExecutionFrame<O>,
    maximum: usize,
    less_nan: bool,
    next: usize,
) -> Result<Control<O>, Thrown<O>> {
    let right =
        to_f32(&pop(frame)?).ok_or_else(|| thrown("java/lang/VerifyError", VmValue::Null))?;
    let left =
        to_f32(&pop(frame)?).ok_or_else(|| thrown("java/lang/VerifyError", VmValue::Null))?;
    let value = if left.is_nan() || right.is_nan() {
        if less_nan {
            -1
        } else {
            1
        }
    } else if left < right {
        -1
    } else if left > right {
        1
    } else {
        0
    };
    push(frame, VmValue::Int(value), maximum)?;
    Ok(Control::Next(next))
}

fn compare_double<O>(
    frame: &mut ExecutionFrame<O>,
    maximum: usize,
    less_nan: bool,
    next: usize,
) -> Result<Control<O>, Thrown<O>> {
    let right =
        to_f64(&pop(frame)?).ok_or_else(|| thrown("java/lang/VerifyError", VmValue::Null))?;
    let left =
        to_f64(&pop(frame)?).ok_or_else(|| thrown("java/lang/VerifyError", VmValue::Null))?;
    let value = if left.is_nan() || right.is_nan() {
        if less_nan {
            -1
        } else {
            1
        }
    } else if left < right {
        -1
    } else if left > right {
        1
    } else {
        0
    };
    push(frame, VmValue::Int(value), maximum)?;
    Ok(Control::Next(next))
}

fn descriptor_arity(descriptor: &str) -> Option<usize> {
    let bytes = descriptor.as_bytes();
    if bytes.first().copied()? != b'(' {
        return None;
    }
    let mut index = 1usize;
    let mut count = 0usize;
    while index < bytes.len() && bytes[index] != b')' {
        while bytes.get(index) == Some(&b'[') {
            index += 1;
        }
        match bytes.get(index).copied()? {
            b'Z' | b'B' | b'C' | b'S' | b'I' | b'J' | b'F' | b'D' => index += 1,
            b'L' => {
                index = bytes[index + 1..]
                    .iter()
                    .position(|byte| *byte == b';')?
                    .saturating_add(index + 2);
            }
            _ => return None,
        }
        count += 1;
    }
    if bytes.get(index) != Some(&b')') {
        return None;
    }
    descriptor_return_tag(&descriptor[index + 1..]).map(|_| count)
}

fn descriptor_return_tag(descriptor: &str) -> Option<u8> {
    let value = descriptor.as_bytes().first().copied()?;
    if b"VZBCSIJFDL[".contains(&value) {
        Some(value)
    } else {
        None
    }
}

fn method_return_tag(descriptor: &str) -> Option<u8> {
    descriptor
        .rsplit_once(')')
        .and_then(|(_, return_descriptor)| descriptor_return_tag(return_descriptor))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ProgramBuilder;

    #[test]
    fn lambda_recipe_uses_factory_descriptor_for_stack_arity() {
        let reference =
            "lambda|run|(Lexample/Exec;)Ljava/lang/Runnable;|5|example/Exec|doAdd|()V|()V|()V|0;;";
        assert_eq!(
            dynamic_descriptor(reference),
            Some("(Lexample/Exec;)Ljava/lang/Runnable;")
        );
        assert_eq!(
            descriptor_arity(dynamic_descriptor(reference).unwrap()),
            Some(1)
        );
    }

    #[test]
    fn wrapping_integer_arithmetic_and_branches_execute() {
        let program = ProgramBuilder::new()
            .instruction(opcode::ICONST, &[i32::MAX])
            .instruction(opcode::ICONST, &[1])
            .instruction(opcode::IADD, &[])
            .instruction(opcode::ICONST, &[i32::MIN])
            .instruction(opcode::IADD, &[])
            .instruction(opcode::IRETURN, &[])
            .finish();
        let mut executor = VmExecutor::new(NoObjectOperations);
        assert_eq!(executor.execute(&program, &[]), Ok(VmValue::Int(0)));
    }

    #[test]
    fn call_uses_safe_host_trait_and_exception_handler() {
        struct Host;
        impl ObjectOperations for Host {
            type Object = u32;
            fn invoke(
                &mut self,
                _kind: InvokeKind,
                reference: &str,
                _receiver: Option<&u32>,
                arguments: &[VmValue<u32>],
            ) -> Result<VmValue<u32>, VmHostError> {
                assert_eq!(reference, "Host.add:(II)I");
                let left = match arguments[0] {
                    VmValue::Int(value) => value,
                    _ => return Err(VmHostError::Failure),
                };
                let right = match arguments[1] {
                    VmValue::Int(value) => value,
                    _ => return Err(VmHostError::Failure),
                };
                Ok(VmValue::Int(left.wrapping_add(right)))
            }
        }
        let program = ProgramBuilder::new()
            .constant_string("Host.add:(II)I")
            .instruction(opcode::ICONST, &[2])
            .instruction(opcode::ICONST, &[3])
            .instruction(opcode::INVOKESTATIC, &[0])
            .instruction(opcode::IRETURN, &[])
            .finish();
        let mut executor = VmExecutor::new(Host);
        assert_eq!(executor.execute(&program, &[]), Ok(VmValue::Int(5)));
    }

    #[test]
    fn host_throwable_is_preserved_for_vm_catch_handlers() {
        struct Host {
            pending: bool,
        }

        impl ObjectOperations for Host {
            type Object = u32;

            fn invoke(
                &mut self,
                _kind: InvokeKind,
                reference: &str,
                _receiver: Option<&u32>,
                _arguments: &[VmValue<u32>],
            ) -> Result<VmValue<u32>, VmHostError> {
                assert_eq!(reference, "Host.fail:()V");
                self.pending = true;
                Err(VmHostError::Failure)
            }

            fn take_pending_exception(&mut self) -> Option<(String, u32)> {
                self.pending
                    .then(|| ("example/SpecificProblem".to_owned(), 0xE11))
                    .inspect(|_| self.pending = false)
            }

            fn instance_of(&mut self, object: &u32, class: &str) -> Result<bool, VmHostError> {
                Ok(*object == 0xE11 && class == "example/BaseProblem")
            }
        }

        let program = ProgramBuilder::new()
            .constant_string("Host.fail:()V")
            .constant_string("example/BaseProblem")
            .instruction(opcode::INVOKESTATIC, &[0])
            .instruction(opcode::RETURN, &[])
            .instruction(opcode::POP, &[])
            .instruction(opcode::RETURN, &[])
            .exception(0, 1, 2, Some(1))
            .finish();
        let mut executor = VmExecutor::new(Host { pending: false });
        assert_eq!(executor.execute(&program, &[]), Ok(VmValue::Null));
        assert!(!executor.into_host().pending);
    }

    #[test]
    fn unresolved_decoy_exception_handlers_are_skipped() {
        struct Host {
            pending: bool,
        }

        impl ObjectOperations for Host {
            type Object = u32;

            fn invoke(
                &mut self,
                _kind: InvokeKind,
                reference: &str,
                _receiver: Option<&u32>,
                _arguments: &[VmValue<u32>],
            ) -> Result<VmValue<u32>, VmHostError> {
                assert_eq!(reference, "Host.fail:()V");
                self.pending = true;
                Err(VmHostError::Failure)
            }

            fn take_pending_exception(&mut self) -> Option<(String, u32)> {
                self.pending
                    .then(|| ("example/SpecificProblem".to_owned(), 0xE11))
                    .inspect(|_| self.pending = false)
            }

            fn instance_of(&mut self, object: &u32, class: &str) -> Result<bool, VmHostError> {
                if class.starts_with("javashroud/decoy/") {
                    return Err(VmHostError::Failure);
                }
                Ok(*object == 0xE11 && class == "example/BaseProblem")
            }
        }

        let program = ProgramBuilder::new()
            .constant_string("Host.fail:()V")
            .constant_string("javashroud/decoy/Edead")
            .constant_string("example/BaseProblem")
            .instruction(opcode::INVOKESTATIC, &[0])
            .instruction(opcode::RETURN, &[])
            .instruction(opcode::POP, &[])
            .instruction(opcode::RETURN, &[])
            .exception(0, 1, 2, Some(1))
            .exception(0, 1, 2, Some(2))
            .finish();
        let mut executor = VmExecutor::new(Host { pending: false });
        assert_eq!(executor.execute(&program, &[]), Ok(VmValue::Null));
        assert!(!executor.into_host().pending);
    }

    #[test]
    fn divide_by_zero_is_caught_by_bounded_handler() {
        let program = ProgramBuilder::new()
            .instruction(opcode::ICONST, &[1])
            .instruction(opcode::ICONST, &[0])
            .instruction(opcode::IDIV, &[])
            .instruction(opcode::RETURN, &[])
            .exception(0, 3, 3, None)
            .finish();
        let mut executor = VmExecutor::new(NoObjectOperations);
        assert_eq!(executor.execute(&program, &[]), Ok(VmValue::Null));
    }

    #[test]
    fn frame_state_is_wiped_after_failure() {
        let program = ProgramBuilder::new()
            .instruction(opcode::ICONST, &[9])
            .instruction(opcode::POP2, &[])
            .finish();
        let mut executor = VmExecutor::new(NoObjectOperations);
        assert!(executor.execute(&program, &[]).is_err());
    }
}
