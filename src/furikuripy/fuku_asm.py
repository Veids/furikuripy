from enum import Enum
from typing import Optional, List, Callable
from pydantic import BaseModel, ConfigDict

from .fuku_misc import FUKU_ASSEMBLER_ARCH, UNUSUAL_DATASET
from .fuku_inst import FukuInst, FukuCodeLabel
from .fuku_code_holder import FukuCodeHolder
from .x86.fuku_operand import FukuPrefix, FukuOperandSize
from .x86.fuku_asm_ctx import FukuAsmCtx
from .x86.fuku_asm_body import FukuAsmBody
from .x86.fuku_type import FukuType, FukuT0Types
from .x86.misc import FukuCondition
from .x86.fuku_register import FukuRegisterIndex


def get_minimal_op_size(dst: FukuType | FukuAsmCtx, src: FukuType) -> FukuOperandSize:
    if isinstance(dst, FukuType):
        match dst.type:
            case FukuT0Types.FUKU_T0_REGISTER:
                match src.type:
                    case FukuT0Types.FUKU_T0_REGISTER:
                        return dst.size

                    case FukuT0Types.FUKU_T0_OPERAND:
                        return src.size

                    case FukuT0Types.FUKU_T0_IMMEDIATE:
                        return dst.size

            case FukuT0Types.FUKU_T0_OPERAND:
                match src.type:
                    case FukuT0Types.FUKU_T0_REGISTER:
                        return dst.size

                    case FukuT0Types.FUKU_T0_IMMEDIATE:
                        return dst.size
    else:
        match src.type:
            case FukuT0Types.FUKU_T0_REGISTER:
                return src.size

            case FukuT0Types.FUKU_T0_OPERAND:
                return src.size

            case FukuT0Types.FUKU_T0_IMMEDIATE:
                return (
                    FukuOperandSize.SIZE_32
                    if dst.arch == FUKU_ASSEMBLER_ARCH.X86
                    else FukuOperandSize.SIZE_64
                )

    return FukuOperandSize.SIZE_0


class FukuAsmHoldType(Enum):
    ASSEMBLER_HOLD_TYPE_NOOVERWRITE = 0
    ASSEMBLER_HOLD_TYPE_FIRST_OVERWRITE = 1
    ASSEMBLER_HOLD_TYPE_FULL_OVERWRITE = 2


class FukuAsm(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    inst: FukuInst
    context: FukuAsmCtx

    hold_type: FukuAsmHoldType = FukuAsmHoldType.ASSEMBLER_HOLD_TYPE_NOOVERWRITE
    code_holder: Optional[FukuCodeHolder] = None
    position: int = 0

    first_emit: bool = True
    has_label_to_set: bool = False

    _label: Optional[FukuCodeLabel] = None
    prefixes: List[FukuPrefix] = list()

    asm: FukuAsmBody = FukuAsmBody()

    def __init__(self, arch=FUKU_ASSEMBLER_ARCH.X86, **kwargs):
        inst = FukuInst()
        super().__init__(
            inst=inst,
            context=FukuAsmCtx(arch=arch, short_cfg=0xFF, inst=inst),
            **kwargs,
        )

    def set_holder(self, code_holder: FukuCodeHolder, hold_type: FukuAsmHoldType):
        self.code_holder = code_holder
        self.hold_type = hold_type
        self.position = 0

    @property
    def label(self) -> Optional[FukuCodeLabel]:
        return self._label

    @label.setter
    def label(self, label: FukuCodeLabel):
        self.has_label_to_set = True
        self._label = label

    @label.deleter
    def label(self):
        self.has_label_to_set = False
        del self._label

    def on_emit(self, dst: Optional[FukuType] = None, src: Optional[FukuType] = None):
        if dst is not None:
            if dst.type == FukuT0Types.FUKU_T0_OPERAND:
                if dst.segment != FukuPrefix.FUKU_PREFIX_NONE:
                    self.prefixes.append(dst.segment)
            elif src is not None and src.type == FukuT0Types.FUKU_T0_OPERAND:
                if src.segment != FukuPrefix.FUKU_PREFIX_NONE:
                    self.prefixes.append(src.segment)

        if self.code_holder is None:
            return

        if self.hold_type == FukuAsmHoldType.ASSEMBLER_HOLD_TYPE_FULL_OVERWRITE:
            if self.position == len(self.code_holder.instructions):
                inst = FukuInst()
                self.code_holder.instructions.append(inst)
                self.context.inst = inst
                self.position += 1
            else:
                self.context.inst = self.code_holder.instructions[self.position]
                self.position += 1
        else:
            if (
                self.hold_type == FukuAsmHoldType.ASSEMBLER_HOLD_TYPE_FIRST_OVERWRITE
                and self.first_emit
            ):
                if self.position == len(self.code_holder.instructions):
                    inst = FukuInst()
                    self.code_holder.instructions.append(inst)
                    self.context.inst = inst
                    self.position += 1
                else:
                    self.context.inst = self.code_holder.instructions[self.position]
                    self.position += 1

                self.first_emit = False
            else:
                inst = FukuInst()
                self.context.inst = inst
                if self.position == len(self.code_holder.instructions):
                    self.code_holder.instructions.append(inst)
                    self.position += 1
                else:
                    self.code_holder.instructions.insert(self.position, inst)
                    self.position += 1

    def on_new_chain_item(self) -> FukuAsmCtx:
        if len(self.prefixes):
            opcode = (
                bytearray([x.value for x in self.prefixes]) + self.context.inst.opcode
            )

            if self.context.displacment_offset:
                self.context.displacment_offset += len(self.prefixes)

            if self.context.immediate_offset:
                self.context.immediate_offset += len(self.prefixes)

            self.context.inst.opcode = opcode
            self.prefixes.clear()

        if self.has_label_to_set:
            self.context.inst.label = self.label

            if self.code_holder:
                self.label.has_linked_instruction = True

            del self.label

        return self.context

    def _fuku_assembler_command_1op_graph(
        self,
        dst: FukuType,
        op_b_r: Callable,
        op_b_op: Callable,
        op_b_imm: Callable,
        op_w_r: Callable,
        op_w_op: Callable,
        op_w_imm: Callable,
        op_dw_r: Callable,
        op_dw_op: Callable,
        op_dw_imm: Callable,
        op_qw_r: Callable,
        op_qw_op: Callable,
        op_qw_imm: Callable,
    ):
        self.on_emit(dst)
        match get_minimal_op_size(self.context, dst):
            case FukuOperandSize.SIZE_8:
                match dst.type:
                    case FukuT0Types.FUKU_T0_REGISTER:
                        op_b_r()

                    case FukuT0Types.FUKU_T0_OPERAND:
                        op_b_op()

                    case FukuT0Types.FUKU_T0_IMMEDIATE:
                        op_b_imm()

                    case _:
                        UNUSUAL_DATASET()

            case FukuOperandSize.SIZE_16:
                match dst.type:
                    case FukuT0Types.FUKU_T0_REGISTER:
                        op_w_r()

                    case FukuT0Types.FUKU_T0_OPERAND:
                        op_w_op()

                    case FukuT0Types.FUKU_T0_IMMEDIATE:
                        op_w_imm()

                    case _:
                        UNUSUAL_DATASET()

            case FukuOperandSize.SIZE_32:
                match dst.type:
                    case FukuT0Types.FUKU_T0_REGISTER:
                        op_dw_r()

                    case FukuT0Types.FUKU_T0_OPERAND:
                        op_dw_op()

                    case FukuT0Types.FUKU_T0_IMMEDIATE:
                        op_dw_imm()

                    case _:
                        UNUSUAL_DATASET()

            case FukuOperandSize.SIZE_64:
                match dst.type:
                    case FukuT0Types.FUKU_T0_REGISTER:
                        op_qw_r()

                    case FukuT0Types.FUKU_T0_OPERAND:
                        op_qw_op()

                    case FukuT0Types.FUKU_T0_IMMEDIATE:
                        op_qw_imm()

                    case _:
                        UNUSUAL_DATASET()

            case _:
                UNUSUAL_DATASET()

    def _iced_assembler_command_2op_graph(
        self,
        dst: FukuType,
        src: FukuType,
        op_b_r_r: Callable,
        op_b_r_op: Callable,
        op_b_r_imm: Callable,
        op_b_op_r: Callable,
        op_b_op_imm: Callable,
        op_w_r_r: Callable,
        op_w_r_op: Callable,
        op_w_r_imm: Callable,
        op_w_op_r: Callable,
        op_w_op_imm: Callable,
        op_dw_r_r: Callable,
        op_dw_r_op: Callable,
        op_dw_r_imm: Callable,
        op_dw_op_r: Callable,
        op_dw_op_imm: Callable,
        op_qw_r_r: Callable,
        op_qw_r_op: Callable,
        op_qw_r_imm: Callable,
        op_qw_op_r: Callable,
        op_qw_op_imm: Callable,
    ):
        self.on_emit()
        match get_minimal_op_size(dst, src):
            case FukuOperandSize.SIZE_8:
                match dst.type:
                    case FukuT0Types.FUKU_T0_REGISTER:
                        match src.type:
                            case FukuT0Types.FUKU_T0_REGISTER:
                                op_b_r_r()

                            case FukuT0Types.FUKU_T0_OPERAND:
                                op_b_r_op()

                            case FukuT0Types.FUKU_T0_IMMEDIATE:
                                op_b_r_imm()

                            case _:
                                UNUSUAL_DATASET()

                    case FukuT0Types.FUKU_T0_OPERAND:
                        match src.type:
                            case FukuT0Types.FUKU_T0_REGISTER:
                                op_b_op_r()

                            case FukuT0Types.FUKU_T0_IMMEDIATE:
                                op_b_op_imm()

                            case _:
                                UNUSUAL_DATASET()

                    case _:
                        UNUSUAL_DATASET()

            case FukuOperandSize.SIZE_16:
                match dst.type:
                    case FukuT0Types.FUKU_T0_REGISTER:
                        match src.type:
                            case FukuT0Types.FUKU_T0_REGISTER:
                                op_w_r_r()

                            case FukuT0Types.FUKU_T0_OPERAND:
                                op_w_r_op()

                            case FukuT0Types.FUKU_T0_IMMEDIATE:
                                op_w_r_imm()

                            case _:
                                UNUSUAL_DATASET()

                    case FukuT0Types.FUKU_T0_OPERAND:
                        match src.type:
                            case FukuT0Types.FUKU_T0_REGISTER:
                                op_w_op_r()

                            case FukuT0Types.FUKU_T0_IMMEDIATE:
                                op_w_op_imm()

                            case _:
                                UNUSUAL_DATASET()

                    case _:
                        UNUSUAL_DATASET()

            case FukuOperandSize.SIZE_32:
                match dst.type:
                    case FukuT0Types.FUKU_T0_REGISTER:
                        match src.type:
                            case FukuT0Types.FUKU_T0_REGISTER:
                                op_dw_r_r()

                            case FukuT0Types.FUKU_T0_OPERAND:
                                op_dw_r_op()

                            case FukuT0Types.FUKU_T0_IMMEDIATE:
                                op_dw_r_imm()

                            case _:
                                UNUSUAL_DATASET()

                    case FukuT0Types.FUKU_T0_OPERAND:
                        match src.type:
                            case FukuT0Types.FUKU_T0_REGISTER:
                                op_dw_op_r()

                            case FukuT0Types.FUKU_T0_IMMEDIATE:
                                op_dw_op_imm()

                            case _:
                                UNUSUAL_DATASET()

                    case _:
                        UNUSUAL_DATASET()

            case FukuOperandSize.SIZE_64:
                match dst.type:
                    case FukuT0Types.FUKU_T0_REGISTER:
                        match src.type:
                            case FukuT0Types.FUKU_T0_REGISTER:
                                op_qw_r_r()

                            case FukuT0Types.FUKU_T0_OPERAND:
                                op_qw_r_op()

                            case FukuT0Types.FUKU_T0_IMMEDIATE:
                                op_qw_r_imm()

                            case _:
                                UNUSUAL_DATASET()

                    case FukuT0Types.FUKU_T0_OPERAND:
                        match src.type:
                            case FukuT0Types.FUKU_T0_REGISTER:
                                op_qw_op_r()

                            case FukuT0Types.FUKU_T0_IMMEDIATE:
                                op_qw_op_imm()

                            case _:
                                UNUSUAL_DATASET()

                    case _:
                        UNUSUAL_DATASET()

            case _:
                UNUSUAL_DATASET()

    def _fuku_assembler_command_2op_graph(
        self,
        dst: FukuType,
        src: FukuType,
        op_b_r_r: Callable,
        op_b_r_op: Callable,
        op_b_r_imm: Callable,
        op_b_op_r: Callable,
        op_b_op_imm: Callable,
        op_w_r_r: Callable,
        op_w_r_op: Callable,
        op_w_r_imm: Callable,
        op_w_op_r: Callable,
        op_w_op_imm: Callable,
        op_dw_r_r: Callable,
        op_dw_r_op: Callable,
        op_dw_r_imm: Callable,
        op_dw_op_r: Callable,
        op_dw_op_imm: Callable,
        op_qw_r_r: Callable,
        op_qw_r_op: Callable,
        op_qw_r_imm: Callable,
        op_qw_op_r: Callable,
        op_qw_op_imm: Callable,
    ):
        self.on_emit(dst, src)
        match get_minimal_op_size(dst, src):
            case FukuOperandSize.SIZE_8:
                match dst.type:
                    case FukuT0Types.FUKU_T0_REGISTER:
                        match src.type:
                            case FukuT0Types.FUKU_T0_REGISTER:
                                op_b_r_r()

                            case FukuT0Types.FUKU_T0_OPERAND:
                                op_b_r_op()

                            case FukuT0Types.FUKU_T0_IMMEDIATE:
                                op_b_r_imm()

                            case _:
                                UNUSUAL_DATASET()

                    case FukuT0Types.FUKU_T0_OPERAND:
                        match src.type:
                            case FukuT0Types.FUKU_T0_REGISTER:
                                op_b_op_r()

                            case FukuT0Types.FUKU_T0_IMMEDIATE:
                                op_b_op_imm()

                            case _:
                                UNUSUAL_DATASET()

                    case _:
                        UNUSUAL_DATASET()

            case FukuOperandSize.SIZE_16:
                match dst.type:
                    case FukuT0Types.FUKU_T0_REGISTER:
                        match src.type:
                            case FukuT0Types.FUKU_T0_REGISTER:
                                op_w_r_r()

                            case FukuT0Types.FUKU_T0_OPERAND:
                                op_w_r_op()

                            case FukuT0Types.FUKU_T0_IMMEDIATE:
                                op_w_r_imm()

                            case _:
                                UNUSUAL_DATASET()

                    case FukuT0Types.FUKU_T0_OPERAND:
                        match src.type:
                            case FukuT0Types.FUKU_T0_REGISTER:
                                op_w_op_r()

                            case FukuT0Types.FUKU_T0_IMMEDIATE:
                                op_w_op_imm()

                            case _:
                                UNUSUAL_DATASET()

                    case _:
                        UNUSUAL_DATASET()

            case FukuOperandSize.SIZE_32:
                match dst.type:
                    case FukuT0Types.FUKU_T0_REGISTER:
                        match src.type:
                            case FukuT0Types.FUKU_T0_REGISTER:
                                op_dw_r_r()

                            case FukuT0Types.FUKU_T0_OPERAND:
                                op_dw_r_op()

                            case FukuT0Types.FUKU_T0_IMMEDIATE:
                                op_dw_r_imm()

                            case _:
                                UNUSUAL_DATASET()

                    case FukuT0Types.FUKU_T0_OPERAND:
                        match src.type:
                            case FukuT0Types.FUKU_T0_REGISTER:
                                op_dw_op_r()

                            case FukuT0Types.FUKU_T0_IMMEDIATE:
                                op_dw_op_imm()

                            case _:
                                UNUSUAL_DATASET()

                    case _:
                        UNUSUAL_DATASET()

            case FukuOperandSize.SIZE_64:
                match dst.type:
                    case FukuT0Types.FUKU_T0_REGISTER:
                        match src.type:
                            case FukuT0Types.FUKU_T0_REGISTER:
                                op_qw_r_r()

                            case FukuT0Types.FUKU_T0_OPERAND:
                                op_qw_r_op()

                            case FukuT0Types.FUKU_T0_IMMEDIATE:
                                op_qw_r_imm()

                            case _:
                                UNUSUAL_DATASET()

                    case FukuT0Types.FUKU_T0_OPERAND:
                        match src.type:
                            case FukuT0Types.FUKU_T0_REGISTER:
                                op_qw_op_r()

                            case FukuT0Types.FUKU_T0_IMMEDIATE:
                                op_qw_op_imm()

                            case _:
                                UNUSUAL_DATASET()

                    case _:
                        UNUSUAL_DATASET()

            case _:
                UNUSUAL_DATASET()

    def mov(self, dst: FukuType, src: FukuType) -> FukuAsmCtx:
        self._fuku_assembler_command_2op_graph(
            dst,
            src,
            lambda: self.asm.mov_b(self.context, dst.register, src.register),
            lambda: self.asm.mov_b(self.context, dst.register, src.operand),
            lambda: self.asm.mov_b(self.context, dst.register, src.immediate),
            lambda: self.asm.mov_b(self.context, dst.operand, src.register),
            lambda: self.asm.mov_b(self.context, dst.operand, src.immediate),
            lambda: self.asm.mov_w(self.context, dst.register, src.register),
            lambda: self.asm.mov_w(self.context, dst.register, src.operand),
            lambda: self.asm.mov_w(self.context, dst.register, src.immediate),
            lambda: self.asm.mov_w(self.context, dst.operand, src.register),
            lambda: self.asm.mov_w(self.context, dst.operand, src.immediate),
            lambda: self.asm.mov_dw(self.context, dst.register, src.register),
            lambda: self.asm.mov_dw(self.context, dst.register, src.operand),
            lambda: self.asm.mov_dw(self.context, dst.register, src.immediate),
            lambda: self.asm.mov_dw(self.context, dst.operand, src.register),
            lambda: self.asm.mov_dw(self.context, dst.operand, src.immediate),
            lambda: self.asm.mov_qw(self.context, dst.register, src.register),
            lambda: self.asm.mov_qw(self.context, dst.register, src.operand),
            lambda: self.asm.mov_qw(self.context, dst.register, src.immediate),
            lambda: self.asm.mov_qw(self.context, dst.operand, src.register),
            lambda: self.asm.mov_qw(self.context, dst.operand, src.immediate),
        )

        return self.on_new_chain_item()

    def cmovcc(self, cond: FukuCondition, dst: FukuType, src: FukuType) -> FukuAsmCtx:
        self._fuku_assembler_command_2op_graph(
            dst,
            src,
            lambda: UNUSUAL_DATASET(),
            lambda: UNUSUAL_DATASET(),
            lambda: UNUSUAL_DATASET(),
            lambda: UNUSUAL_DATASET(),
            lambda: UNUSUAL_DATASET(),
            lambda: self.asm.cmovcc_w(self.context, cond, dst.register, src.register),
            lambda: self.asm.cmovcc_w(self.context, cond, dst.register, src.operand),
            lambda: UNUSUAL_DATASET(),
            lambda: UNUSUAL_DATASET(),
            lambda: UNUSUAL_DATASET(),
            lambda: self.asm.cmovcc_dw(self.context, cond, dst.register, src.register),
            lambda: self.asm.cmovcc_dw(self.context, cond, dst.register, src.operand),
            lambda: UNUSUAL_DATASET(),
            lambda: UNUSUAL_DATASET(),
            lambda: UNUSUAL_DATASET(),
            lambda: self.asm.cmovcc_qw(self.context, cond, dst.register, src.register),
            lambda: self.asm.cmovcc_qw(self.context, cond, dst.register, src.operand),
            lambda: UNUSUAL_DATASET(),
            lambda: UNUSUAL_DATASET(),
            lambda: UNUSUAL_DATASET(),
        )

        return self.on_new_chain_item()

    def xchg(self, dst: FukuType, src: FukuType) -> FukuAsmCtx:
        self._fuku_assembler_command_2op_graph(
            dst,
            src,
            lambda: self.asm.xchg_b(self.context, dst.register, src.register),
            lambda: self.asm.xchg_b(self.context, src.operand, dst.register),
            lambda: UNUSUAL_DATASET(),
            lambda: self.asm.xchg_b(self.context, dst.operand, src.register),
            lambda: UNUSUAL_DATASET(),
            lambda: self.asm.xchg_w(self.context, dst.register, src.register),
            lambda: self.asm.xchg_w(self.context, src.operand, dst.register),
            lambda: UNUSUAL_DATASET(),
            lambda: self.asm.xchg_w(self.context, dst.operand, src.register),
            lambda: UNUSUAL_DATASET(),
            lambda: self.asm.xchg_dw(self.context, dst.register, src.register),
            lambda: self.asm.xchg_dw(self.context, src.operand, dst.register),
            lambda: UNUSUAL_DATASET(),
            lambda: self.asm.xchg_dw(self.context, dst.operand, src.register),
            lambda: UNUSUAL_DATASET(),
            lambda: self.asm.xchg_qw(self.context, dst.register, src.register),
            lambda: self.asm.xchg_qw(self.context, src.operand, dst.register),
            lambda: UNUSUAL_DATASET(),
            lambda: self.asm.xchg_qw(self.context, dst.operand, src.register),
            lambda: UNUSUAL_DATASET(),
        )

        return self.on_new_chain_item()

    def bswap(self, dst: FukuType) -> FukuAsmCtx:
        self._fuku_assembler_command_1op_graph(
            dst,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            lambda: self.asm.bswap_w(self.context, dst.register),
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            lambda: self.asm.bswap_dw(self.context, dst.register),
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            lambda: self.asm.bswap_qw(self.context, dst.register),
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
        )

        return self.on_new_chain_item()

    def xadd(self, dst: FukuType, src: FukuType) -> FukuAsmCtx:
        self._fuku_assembler_command_2op_graph(
            dst,
            src,
            lambda: self.asm.xadd_b(self.context, dst.register, src.register),
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            lambda: self.asm.xadd_b(self.context, dst.operand, src.register),
            UNUSUAL_DATASET,
            lambda: self.asm.xadd_w(self.context, dst.register, src.register),
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            lambda: self.asm.xadd_w(self.context, dst.operand, src.register),
            UNUSUAL_DATASET,
            lambda: self.asm.xadd_dw(self.context, dst.register, src.register),
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            lambda: self.asm.xadd_dw(self.context, dst.operand, src.register),
            UNUSUAL_DATASET,
            lambda: self.asm.xadd_qw(self.context, dst.register, src.register),
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            lambda: self.asm.xadd_qw(self.context, dst.operand, src.register),
            UNUSUAL_DATASET,
        )

        return self.on_new_chain_item()

    def cmpxchg(self, dst: FukuType, src: FukuType) -> FukuAsmCtx:
        self._fuku_assembler_command_2op_graph(
            dst,
            src,
            lambda: self.asm.cmpxchg_b(self.context, dst.register, src.register),
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            lambda: self.asm.cmpxchg_b(self.context, dst.operand, src.register),
            UNUSUAL_DATASET,
            lambda: self.asm.cmpxchg_w(self.context, dst.register, src.register),
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            lambda: self.asm.cmpxchg_w(self.context, dst.operand, src.register),
            UNUSUAL_DATASET,
            lambda: self.asm.cmpxchg_dw(self.context, dst.register, src.register),
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            lambda: self.asm.cmpxchg_dw(self.context, dst.operand, src.register),
            UNUSUAL_DATASET,
            lambda: self.asm.cmpxchg_qw(self.context, dst.register, src.register),
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            lambda: self.asm.cmpxchg_qw(self.context, dst.operand, src.register),
            UNUSUAL_DATASET,
        )

        return self.on_new_chain_item()

    def cmpxchg8b(self, dst: FukuType) -> FukuAsmCtx:
        self._fuku_assembler_command_1op_graph(
            dst,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            lambda: self.asm.cmpxchg8b(self.context, dst.operand),
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
        )

        return self.on_new_chain_item()

    def cmpxchg16b(self, dst: FukuType) -> FukuAsmCtx:
        self._fuku_assembler_command_1op_graph(
            dst,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            lambda: self.asm.cmpxchg16b(self.context, dst.operand),
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
        )

        return self.on_new_chain_item()

    def push(self, src: FukuType) -> FukuAsmCtx:
        self._fuku_assembler_command_1op_graph(
            src,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            lambda: self.asm.push_w(self.context, src.register),
            lambda: self.asm.push_w(self.context, src.operand),
            lambda: self.asm.push_w(self.context, src.immediate),
            lambda: self.asm.push_dw(self.context, src.register),
            lambda: self.asm.push_dw(self.context, src.operand),
            lambda: self.asm.push_dw(self.context, src.immediate),
            lambda: self.asm.push_qw(self.context, src.register),
            lambda: self.asm.push_qw(self.context, src.operand),
            lambda: self.asm.push_qw(self.context, src.immediate),
        )

        return self.on_new_chain_item()

    def pop(self, dst: FukuType) -> FukuAsmCtx:
        self._fuku_assembler_command_1op_graph(
            dst,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            lambda: self.asm.pop_w(self.context, dst.register),
            lambda: self.asm.pop_w(self.context, dst.operand),
            UNUSUAL_DATASET,
            lambda: self.asm.pop_dw(self.context, dst.register),
            lambda: self.asm.pop_dw(self.context, dst.operand),
            UNUSUAL_DATASET,
            lambda: self.asm.pop_qw(self.context, dst.register),
            lambda: self.asm.pop_qw(self.context, dst.operand),
            UNUSUAL_DATASET,
        )

        return self.on_new_chain_item()

    def cwd(self) -> FukuAsmCtx:
        self.on_emit()
        self.asm.cwd(self.context)
        return self.on_new_chain_item()

    def cdq(self) -> FukuAsmCtx:
        self.on_emit()
        self.asm.cdq(self.context)
        return self.on_new_chain_item()

    def cqo(self) -> FukuAsmCtx:
        self.on_emit()
        self.asm.cqo(self.context)
        return self.on_new_chain_item()

    def cbw(self) -> FukuAsmCtx:
        self.on_emit()
        self.asm.cbw(self.context)
        return self.on_new_chain_item()

    def cwde(self) -> FukuAsmCtx:
        self.on_emit()
        self.asm.cwde(self.context)
        return self.on_new_chain_item()

    def cdqe(self) -> FukuAsmCtx:
        self.on_emit()
        self.asm.cdqe(self.context)
        return self.on_new_chain_item()

    def movzx(self, dst: FukuType, src: FukuType) -> FukuAsmCtx:
        self._fuku_assembler_command_2op_graph(
            dst,
            src,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            lambda: self.asm.movzx_byte_w(self.context, dst.register, src.register),
            lambda: self.asm.movzx_byte_w(self.context, dst.register, src.operand),
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            (lambda: self.asm.movzx_byte_dw(self.context, dst.register, src.register))
            if src.register.size.value == 1
            else (
                lambda: self.asm.movzx_word_dw(self.context, dst.register, src.register)
            ),
            (lambda: self.asm.movzx_byte_dw(self.context, dst.register, src.operand))
            if src.operand.size.value == 1
            else (
                lambda: self.asm.movzx_word_dw(self.context, dst.register, src.operand)
            ),
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            (lambda: self.asm.movzx_byte_qw(self.context, dst.register, src.register))
            if src.register.size.value == 1
            else (
                lambda: self.asm.movzx_word_qw(self.context, dst.register, src.register)
            ),
            (lambda: self.asm.movzx_byte_qw(self.context, dst.register, src.operand))
            if src.operand.size.value == 1
            else (
                lambda: self.asm.movzx_word_qw(self.context, dst.register, src.operand)
            ),
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
        )

        return self.on_new_chain_item()

    def movsx(self, dst: FukuType, src: FukuType) -> FukuAsmCtx:
        self._fuku_assembler_command_2op_graph(
            dst,
            src,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            lambda: self.asm.movsx_byte_w(self.context, dst.register, src.register),
            lambda: self.asm.movsx_byte_w(self.context, dst.register, src.operand),
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            (lambda: self.asm.movsx_byte_dw(self.context, dst.register, src.register))
            if src.register.size.value == 1
            else (
                lambda: self.asm.movsx_word_dw(self.context, dst.register, src.register)
            ),
            (lambda: self.asm.movsx_byte_dw(self.context, dst.register, src.operand))
            if src.operand.size.value == 1
            else (
                lambda: self.asm.movsx_word_dw(self.context, dst.register, src.operand)
            ),
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            (lambda: self.asm.movsx_byte_qw(self.context, dst.register, src.register))
            if src.register.size.value == 1
            else (
                lambda: self.asm.movsx_word_qw(self.context, dst.register, src.register)
            ),
            (lambda: self.asm.movsx_byte_qw(self.context, dst.register, src.operand))
            if src.operand.size.value == 1
            else (
                lambda: self.asm.movsx_word_qw(self.context, dst.register, src.operand)
            ),
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
        )

        return self.on_new_chain_item()

    def movsxd(self, dst: FukuType, src: FukuType) -> FukuAsmCtx:
        self._fuku_assembler_command_2op_graph(
            dst,
            src,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            lambda: self.asm.movsxd_word_w(self.context, dst.register, src.register),
            lambda: self.asm.movsxd_word_w(self.context, dst.register, src.operand),
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            lambda: self.asm.movsxd_dword_dw(self.context, dst.register, src.register),
            lambda: self.asm.movsxd_dword_dw(self.context, dst.register, src.operand),
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            lambda: self.asm.movsxd_dword_qw(self.context, dst.register, src.register),
            lambda: self.asm.movsxd_dword_qw(self.context, dst.register, src.operand),
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
        )

        return self.on_new_chain_item()

    # Binary Arithmetic Instructions
    def adcx(self, dst: FukuType, src: FukuType) -> FukuAsmCtx:
        self._fuku_assembler_command_2op_graph(
            dst,
            src,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            lambda: self.asm.adcx_dw(self.context, dst.register, src.register),
            lambda: self.asm.adcx_dw(self.context, dst.register, src.operand),
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            lambda: self.asm.adcx_qw(self.context, dst.register, src.register),
            lambda: self.asm.adcx_qw(self.context, dst.register, src.operand),
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
        )

        return self.on_new_chain_item()

    def adox(self, dst: FukuType, src: FukuType) -> FukuAsmCtx:
        self._fuku_assembler_command_2op_graph(
            dst,
            src,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            lambda: self.asm.adcx_dw(self.context, dst.register, src.register),
            lambda: self.asm.adcx_dw(self.context, dst.register, src.operand),
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            lambda: self.asm.adcx_qw(self.context, dst.register, src.register),
            lambda: self.asm.adcx_qw(self.context, dst.register, src.operand),
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
        )

        return self.on_new_chain_item()

    def add(self, dst: FukuType, src: FukuType) -> FukuAsmCtx:
        # lambda: Instruction.create_reg_mem(Code.ADD_R8_RM8, Register.CL, MemoryOperand(Register.RDX, Register.R12))
        self._fuku_assembler_command_2op_graph(
            dst,
            src,
            lambda: self.asm.add_b(self.context, dst.register, src.register),
            lambda: self.asm.add_b(self.context, dst.register, src.operand),
            lambda: self.asm.add_b(self.context, dst.register, src.immediate),
            lambda: self.asm.add_b(self.context, dst.operand, src.register),
            lambda: self.asm.add_b(self.context, dst.operand, src.immediate),
            lambda: self.asm.add_w(self.context, dst.register, src.register),
            lambda: self.asm.add_w(self.context, dst.register, src.operand),
            lambda: self.asm.add_w(self.context, dst.register, src.immediate),
            lambda: self.asm.add_w(self.context, dst.operand, src.register),
            lambda: self.asm.add_w(self.context, dst.operand, src.immediate),
            lambda: self.asm.add_dw(self.context, dst.register, src.register),
            lambda: self.asm.add_dw(self.context, dst.register, src.operand),
            lambda: self.asm.add_dw(self.context, dst.register, src.immediate),
            lambda: self.asm.add_dw(self.context, dst.operand, src.register),
            lambda: self.asm.add_dw(self.context, dst.operand, src.immediate),
            lambda: self.asm.add_qw(self.context, dst.register, src.register),
            lambda: self.asm.add_qw(self.context, dst.register, src.operand),
            lambda: self.asm.add_qw(self.context, dst.register, src.immediate),
            lambda: self.asm.add_qw(self.context, dst.operand, src.register),
            lambda: self.asm.add_qw(self.context, dst.operand, src.immediate),
        )

        return self.on_new_chain_item()

    def adc(self, dst: FukuType, src: FukuType) -> FukuAsmCtx:
        self._fuku_assembler_command_2op_graph(
            dst,
            src,
            lambda: self.asm.adc_b(self.context, dst.register, src.register),
            lambda: self.asm.adc_b(self.context, dst.register, src.operand),
            lambda: self.asm.adc_b(self.context, dst.register, src.immediate),
            lambda: self.asm.adc_b(self.context, dst.operand, src.register),
            lambda: self.asm.adc_b(self.context, dst.operand, src.immediate),
            lambda: self.asm.adc_w(self.context, dst.register, src.register),
            lambda: self.asm.adc_w(self.context, dst.register, src.operand),
            lambda: self.asm.adc_w(self.context, dst.register, src.immediate),
            lambda: self.asm.adc_w(self.context, dst.operand, src.register),
            lambda: self.asm.adc_w(self.context, dst.operand, src.immediate),
            lambda: self.asm.adc_dw(self.context, dst.register, src.register),
            lambda: self.asm.adc_dw(self.context, dst.register, src.operand),
            lambda: self.asm.adc_dw(self.context, dst.register, src.immediate),
            lambda: self.asm.adc_dw(self.context, dst.operand, src.register),
            lambda: self.asm.adc_dw(self.context, dst.operand, src.immediate),
            lambda: self.asm.adc_qw(self.context, dst.register, src.register),
            lambda: self.asm.adc_qw(self.context, dst.register, src.operand),
            lambda: self.asm.adc_qw(self.context, dst.register, src.immediate),
            lambda: self.asm.adc_qw(self.context, dst.operand, src.register),
            lambda: self.asm.adc_qw(self.context, dst.operand, src.immediate),
        )

        return self.on_new_chain_item()

    def sub(self, dst: FukuType, src: FukuType) -> FukuAsmCtx:
        self._fuku_assembler_command_2op_graph(
            dst,
            src,
            lambda: self.asm.sub_b(self.context, dst.register, src.register),
            lambda: self.asm.sub_b(self.context, dst.register, src.operand),
            lambda: self.asm.sub_b(self.context, dst.register, src.immediate),
            lambda: self.asm.sub_b(self.context, dst.operand, src.register),
            lambda: self.asm.sub_b(self.context, dst.operand, src.immediate),
            lambda: self.asm.sub_w(self.context, dst.register, src.register),
            lambda: self.asm.sub_w(self.context, dst.register, src.operand),
            lambda: self.asm.sub_w(self.context, dst.register, src.immediate),
            lambda: self.asm.sub_w(self.context, dst.operand, src.register),
            lambda: self.asm.sub_w(self.context, dst.operand, src.immediate),
            lambda: self.asm.sub_dw(self.context, dst.register, src.register),
            lambda: self.asm.sub_dw(self.context, dst.register, src.operand),
            lambda: self.asm.sub_dw(self.context, dst.register, src.immediate),
            lambda: self.asm.sub_dw(self.context, dst.operand, src.register),
            lambda: self.asm.sub_dw(self.context, dst.operand, src.immediate),
            lambda: self.asm.sub_qw(self.context, dst.register, src.register),
            lambda: self.asm.sub_qw(self.context, dst.register, src.operand),
            lambda: self.asm.sub_qw(self.context, dst.register, src.immediate),
            lambda: self.asm.sub_qw(self.context, dst.operand, src.register),
            lambda: self.asm.sub_qw(self.context, dst.operand, src.immediate),
        )

        return self.on_new_chain_item()

    def sbb(self, dst: FukuType, src: FukuType) -> FukuAsmCtx:
        self._fuku_assembler_command_2op_graph(
            dst,
            src,
            lambda: self.asm.sbb_b(self.context, dst.register, src.register),
            lambda: self.asm.sbb_b(self.context, dst.register, src.operand),
            lambda: self.asm.sbb_b(self.context, dst.register, src.immediate),
            lambda: self.asm.sbb_b(self.context, dst.operand, src.register),
            lambda: self.asm.sbb_b(self.context, dst.operand, src.immediate),
            lambda: self.asm.sbb_w(self.context, dst.register, src.register),
            lambda: self.asm.sbb_w(self.context, dst.register, src.operand),
            lambda: self.asm.sbb_w(self.context, dst.register, src.immediate),
            lambda: self.asm.sbb_w(self.context, dst.operand, src.register),
            lambda: self.asm.sbb_w(self.context, dst.operand, src.immediate),
            lambda: self.asm.sbb_dw(self.context, dst.register, src.register),
            lambda: self.asm.sbb_dw(self.context, dst.register, src.operand),
            lambda: self.asm.sbb_dw(self.context, dst.register, src.immediate),
            lambda: self.asm.sbb_dw(self.context, dst.operand, src.register),
            lambda: self.asm.sbb_dw(self.context, dst.operand, src.immediate),
            lambda: self.asm.sbb_qw(self.context, dst.register, src.register),
            lambda: self.asm.sbb_qw(self.context, dst.register, src.operand),
            lambda: self.asm.sbb_qw(self.context, dst.register, src.immediate),
            lambda: self.asm.sbb_qw(self.context, dst.operand, src.register),
            lambda: self.asm.sbb_qw(self.context, dst.operand, src.immediate),
        )

        return self.on_new_chain_item()

    def imul(self, src: FukuType) -> FukuAsmCtx:
        self._fuku_assembler_command_1op_graph(
            src,
            lambda: self.asm.imul_b(self.context, src.register),
            lambda: self.asm.imul_b(self.context, src.operand),
            UNUSUAL_DATASET,
            lambda: self.asm.imul_w(self.context, src.register),
            lambda: self.asm.imul_w(self.context, src.operand),
            UNUSUAL_DATASET,
            lambda: self.asm.imul_dw(self.context, src.register),
            lambda: self.asm.imul_dw(self.context, src.operand),
            UNUSUAL_DATASET,
            lambda: self.asm.imul_qw(self.context, src.register),
            lambda: self.asm.imul_qw(self.context, src.operand),
            UNUSUAL_DATASET,
        )

        return self.on_new_chain_item()

    def mul(self, dst: FukuType) -> FukuAsmCtx:
        self._fuku_assembler_command_1op_graph(
            dst,
            lambda: self.asm.mul_b(self.context, dst.register),
            lambda: self.asm.mul_b(self.context, dst.operand),
            UNUSUAL_DATASET,
            lambda: self.asm.mul_w(self.context, dst.register),
            lambda: self.asm.mul_w(self.context, dst.operand),
            UNUSUAL_DATASET,
            lambda: self.asm.mul_dw(self.context, dst.register),
            lambda: self.asm.mul_dw(self.context, dst.operand),
            UNUSUAL_DATASET,
            lambda: self.asm.mul_qw(self.context, dst.register),
            lambda: self.asm.mul_qw(self.context, dst.operand),
            UNUSUAL_DATASET,
        )

        return self.on_new_chain_item()

    def idiv(self, src: FukuType) -> FukuAsmCtx:
        self._fuku_assembler_command_1op_graph(
            src,
            lambda: self.asm.idiv_b(self.context, src.register),
            lambda: self.asm.idiv_b(self.context, src.operand),
            UNUSUAL_DATASET,
            lambda: self.asm.idiv_w(self.context, src.register),
            lambda: self.asm.idiv_w(self.context, src.operand),
            UNUSUAL_DATASET,
            lambda: self.asm.idiv_dw(self.context, src.register),
            lambda: self.asm.idiv_dw(self.context, src.operand),
            UNUSUAL_DATASET,
            lambda: self.asm.idiv_qw(self.context, src.register),
            lambda: self.asm.idiv_qw(self.context, src.operand),
            UNUSUAL_DATASET,
        )

        return self.on_new_chain_item()

    def div(self, dst: FukuType) -> FukuAsmCtx:
        self._fuku_assembler_command_1op_graph(
            dst,
            lambda: self.asm.div_b(self.context, dst.register),
            lambda: self.asm.div_b(self.context, dst.operand),
            UNUSUAL_DATASET,
            lambda: self.asm.div_w(self.context, dst.register),
            lambda: self.asm.div_w(self.context, dst.operand),
            UNUSUAL_DATASET,
            lambda: self.asm.div_dw(self.context, dst.register),
            lambda: self.asm.div_dw(self.context, dst.operand),
            UNUSUAL_DATASET,
            lambda: self.asm.div_qw(self.context, dst.register),
            lambda: self.asm.div_qw(self.context, dst.operand),
            UNUSUAL_DATASET,
        )

        return self.on_new_chain_item()

    def inc(self, src: FukuType) -> FukuAsmCtx:
        self._fuku_assembler_command_1op_graph(
            src,
            lambda: self.asm.inc_b(self.context, src.register),
            lambda: self.asm.inc_b(self.context, src.operand),
            UNUSUAL_DATASET,
            lambda: self.asm.inc_w(self.context, src.register),
            lambda: self.asm.inc_w(self.context, src.operand),
            UNUSUAL_DATASET,
            lambda: self.asm.inc_dw(self.context, src.register),
            lambda: self.asm.inc_dw(self.context, src.operand),
            UNUSUAL_DATASET,
            lambda: self.asm.inc_qw(self.context, src.register),
            lambda: self.asm.inc_qw(self.context, src.operand),
            UNUSUAL_DATASET,
        )

        return self.on_new_chain_item()

    def dec(self, dst: FukuType) -> FukuAsmCtx:
        self._fuku_assembler_command_1op_graph(
            dst,
            lambda: self.asm.dec_b(self.context, dst.register),
            lambda: self.asm.dec_b(self.context, dst.operand),
            UNUSUAL_DATASET,
            lambda: self.asm.dec_w(self.context, dst.register),
            lambda: self.asm.dec_w(self.context, dst.operand),
            UNUSUAL_DATASET,
            lambda: self.asm.dec_dw(self.context, dst.register),
            lambda: self.asm.dec_dw(self.context, dst.operand),
            UNUSUAL_DATASET,
            lambda: self.asm.dec_qw(self.context, dst.register),
            lambda: self.asm.dec_qw(self.context, dst.operand),
            UNUSUAL_DATASET,
        )

        return self.on_new_chain_item()

    def neg(self, src: FukuType) -> FukuAsmCtx:
        self._fuku_assembler_command_1op_graph(
            src,
            lambda: self.asm.neg_b(self.context, src.register),
            lambda: self.asm.neg_b(self.context, src.operand),
            UNUSUAL_DATASET,
            lambda: self.asm.neg_w(self.context, src.register),
            lambda: self.asm.neg_w(self.context, src.operand),
            UNUSUAL_DATASET,
            lambda: self.asm.neg_dw(self.context, src.register),
            lambda: self.asm.neg_dw(self.context, src.operand),
            UNUSUAL_DATASET,
            lambda: self.asm.neg_qw(self.context, src.register),
            lambda: self.asm.neg_qw(self.context, src.operand),
            UNUSUAL_DATASET,
        )

        return self.on_new_chain_item()

    def cmp(self, dst: FukuType, src: FukuType) -> FukuAsmCtx:
        self._fuku_assembler_command_2op_graph(
            dst,
            src,
            lambda: self.asm.cmp_b(self.context, dst.register, src.register),
            lambda: self.asm.cmp_b(self.context, dst.register, src.operand),
            lambda: self.asm.cmp_b(self.context, dst.register, src.immediate),
            lambda: self.asm.cmp_b(self.context, dst.operand, src.register),
            lambda: self.asm.cmp_b(self.context, dst.operand, src.immediate),
            lambda: self.asm.cmp_w(self.context, dst.register, src.register),
            lambda: self.asm.cmp_w(self.context, dst.register, src.operand),
            lambda: self.asm.cmp_w(self.context, dst.register, src.immediate),
            lambda: self.asm.cmp_w(self.context, dst.operand, src.register),
            lambda: self.asm.cmp_w(self.context, dst.operand, src.immediate),
            lambda: self.asm.cmp_dw(self.context, dst.register, src.register),
            lambda: self.asm.cmp_dw(self.context, dst.register, src.operand),
            lambda: self.asm.cmp_dw(self.context, dst.register, src.immediate),
            lambda: self.asm.cmp_dw(self.context, dst.operand, src.register),
            lambda: self.asm.cmp_dw(self.context, dst.operand, src.immediate),
            lambda: self.asm.cmp_qw(self.context, dst.register, src.register),
            lambda: self.asm.cmp_qw(self.context, dst.register, src.operand),
            lambda: self.asm.cmp_qw(self.context, dst.register, src.immediate),
            lambda: self.asm.cmp_qw(self.context, dst.operand, src.register),
            lambda: self.asm.cmp_qw(self.context, dst.operand, src.immediate),
        )

        return self.on_new_chain_item()

    # Decimal Arithmetic Instructions
    def daa(self) -> FukuAsmCtx:
        self.on_emit()
        self.asm.daa(self.context)
        return self.on_new_chain_item()

    def das(self) -> FukuAsmCtx:
        self.on_emit()
        self.asm.das(self.context)
        return self.on_new_chain_item()

    def aaa(self) -> FukuAsmCtx:
        self.on_emit()
        self.asm.aaa(self.context)
        return self.on_new_chain_item()

    def aas(self) -> FukuAsmCtx:
        self.on_emit()
        self.asm.aas(self.context)
        return self.on_new_chain_item()

    def aam(self, src: FukuType) -> FukuAsmCtx:
        self.on_emit()
        self.asm.aam(self.context, src.immediate)
        return self.on_new_chain_item()

    def aad(self, src: FukuType) -> FukuAsmCtx:
        self.on_emit()
        self.asm.aad(self.context, src.immediate)
        return self.on_new_chain_item()

    # Logical Instructions Instructions
    def and_(self, dst: FukuType, src: FukuType) -> FukuAsmCtx:
        self._fuku_assembler_command_2op_graph(
            dst,
            src,
            lambda: self.asm.and_b(self.context, dst.register, src.register),
            lambda: self.asm.and_b(self.context, dst.register, src.operand),
            lambda: self.asm.and_b(self.context, dst.register, src.immediate),
            lambda: self.asm.and_b(self.context, dst.operand, src.register),
            lambda: self.asm.and_b(self.context, dst.operand, src.immediate),
            lambda: self.asm.and_w(self.context, dst.register, src.register),
            lambda: self.asm.and_w(self.context, dst.register, src.operand),
            lambda: self.asm.and_w(self.context, dst.register, src.immediate),
            lambda: self.asm.and_w(self.context, dst.operand, src.register),
            lambda: self.asm.and_w(self.context, dst.operand, src.immediate),
            lambda: self.asm.and_dw(self.context, dst.register, src.register),
            lambda: self.asm.and_dw(self.context, dst.register, src.operand),
            lambda: self.asm.and_dw(self.context, dst.register, src.immediate),
            lambda: self.asm.and_dw(self.context, dst.operand, src.register),
            lambda: self.asm.and_dw(self.context, dst.operand, src.immediate),
            lambda: self.asm.and_qw(self.context, dst.register, src.register),
            lambda: self.asm.and_qw(self.context, dst.register, src.operand),
            lambda: self.asm.and_qw(self.context, dst.register, src.immediate),
            lambda: self.asm.and_qw(self.context, dst.operand, src.register),
            lambda: self.asm.and_qw(self.context, dst.operand, src.immediate),
        )

        return self.on_new_chain_item()

    def or_(self, dst: FukuType, src: FukuType) -> FukuAsmCtx:
        self._fuku_assembler_command_2op_graph(
            dst,
            src,
            lambda: self.asm.or_b(self.context, dst.register, src.register),
            lambda: self.asm.or_b(self.context, dst.register, src.operand),
            lambda: self.asm.or_b(self.context, dst.register, src.immediate),
            lambda: self.asm.or_b(self.context, dst.operand, src.register),
            lambda: self.asm.or_b(self.context, dst.operand, src.immediate),
            lambda: self.asm.or_w(self.context, dst.register, src.register),
            lambda: self.asm.or_w(self.context, dst.register, src.operand),
            lambda: self.asm.or_w(self.context, dst.register, src.immediate),
            lambda: self.asm.or_w(self.context, dst.operand, src.register),
            lambda: self.asm.or_w(self.context, dst.operand, src.immediate),
            lambda: self.asm.or_dw(self.context, dst.register, src.register),
            lambda: self.asm.or_dw(self.context, dst.register, src.operand),
            lambda: self.asm.or_dw(self.context, dst.register, src.immediate),
            lambda: self.asm.or_dw(self.context, dst.operand, src.register),
            lambda: self.asm.or_dw(self.context, dst.operand, src.immediate),
            lambda: self.asm.or_qw(self.context, dst.register, src.register),
            lambda: self.asm.or_qw(self.context, dst.register, src.operand),
            lambda: self.asm.or_qw(self.context, dst.register, src.immediate),
            lambda: self.asm.or_qw(self.context, dst.operand, src.register),
            lambda: self.asm.or_qw(self.context, dst.operand, src.immediate),
        )

        return self.on_new_chain_item()

    def xor(self, dst: FukuType, src: FukuType) -> FukuAsmCtx:
        self._fuku_assembler_command_2op_graph(
            dst,
            src,
            lambda: self.asm.xor_b(self.context, dst.register, src.register),
            lambda: self.asm.xor_b(self.context, dst.register, src.operand),
            lambda: self.asm.xor_b(self.context, dst.register, src.immediate),
            lambda: self.asm.xor_b(self.context, dst.operand, src.register),
            lambda: self.asm.xor_b(self.context, dst.operand, src.immediate),
            lambda: self.asm.xor_w(self.context, dst.register, src.register),
            lambda: self.asm.xor_w(self.context, dst.register, src.operand),
            lambda: self.asm.xor_w(self.context, dst.register, src.immediate),
            lambda: self.asm.xor_w(self.context, dst.operand, src.register),
            lambda: self.asm.xor_w(self.context, dst.operand, src.immediate),
            lambda: self.asm.xor_dw(self.context, dst.register, src.register),
            lambda: self.asm.xor_dw(self.context, dst.register, src.operand),
            lambda: self.asm.xor_dw(self.context, dst.register, src.immediate),
            lambda: self.asm.xor_dw(self.context, dst.operand, src.register),
            lambda: self.asm.xor_dw(self.context, dst.operand, src.immediate),
            lambda: self.asm.xor_qw(self.context, dst.register, src.register),
            lambda: self.asm.xor_qw(self.context, dst.register, src.operand),
            lambda: self.asm.xor_qw(self.context, dst.register, src.immediate),
            lambda: self.asm.xor_qw(self.context, dst.operand, src.register),
            lambda: self.asm.xor_qw(self.context, dst.operand, src.immediate),
        )

        return self.on_new_chain_item()

    def not_(self, dst: FukuType) -> FukuAsmCtx:
        self._fuku_assembler_command_1op_graph(
            dst,
            lambda: self.asm.not_b(self.context, dst.register),
            lambda: self.asm.not_b(self.context, dst.operand),
            UNUSUAL_DATASET,
            lambda: self.asm.not_w(self.context, dst.register),
            lambda: self.asm.not_w(self.context, dst.operand),
            UNUSUAL_DATASET,
            lambda: self.asm.not_dw(self.context, dst.register),
            lambda: self.asm.not_dw(self.context, dst.operand),
            UNUSUAL_DATASET,
            lambda: self.asm.not_qw(self.context, dst.register),
            lambda: self.asm.not_qw(self.context, dst.operand),
            UNUSUAL_DATASET,
        )

        return self.on_new_chain_item()

    # Shift and Rotate Instructions
    def sar(self, dst: FukuType, src: FukuType) -> FukuAsmCtx:
        if (
            src.type == FukuT0Types.FUKU_T0_REGISTER
            and src.register.index != FukuRegisterIndex.INDEX_CX
        ):
            UNUSUAL_DATASET()

        self._fuku_assembler_command_2op_graph(
            dst,
            src,
            lambda: self.asm.sar_cl_b(self.context, dst.register),
            UNUSUAL_DATASET,
            lambda: self.asm.sar_b(self.context, dst.register, src.immediate),
            lambda: self.asm.sar_cl_b(self.context, dst.operand),
            lambda: self.asm.sar_b(self.context, dst.operand, src.immediate),
            lambda: self.asm.sar_cl_w(self.context, dst.register),
            UNUSUAL_DATASET,
            lambda: self.asm.sar_w(self.context, dst.register, src.immediate),
            lambda: self.asm.sar_cl_w(self.context, dst.operand),
            lambda: self.asm.sar_w(self.context, dst.operand, src.immediate),
            lambda: self.asm.sar_cl_dw(self.context, dst.register),
            UNUSUAL_DATASET,
            lambda: self.asm.sar_dw(self.context, dst.register, src.immediate),
            lambda: self.asm.sar_cl_dw(self.context, dst.operand),
            lambda: self.asm.sar_dw(self.context, dst.operand, src.immediate),
            lambda: self.asm.sar_cl_qw(self.context, dst.register),
            UNUSUAL_DATASET,
            lambda: self.asm.sar_qw(self.context, dst.register, src.immediate),
            lambda: self.asm.sar_cl_qw(self.context, dst.operand),
            lambda: self.asm.sar_qw(self.context, dst.operand, src.immediate),
        )

        return self.on_new_chain_item()

    def shr(self, dst: FukuType, src: FukuType) -> FukuAsmCtx:
        if (
            src.type == FukuT0Types.FUKU_T0_REGISTER
            and src.register.index != FukuRegisterIndex.INDEX_CX
        ):
            UNUSUAL_DATASET()

        self._fuku_assembler_command_2op_graph(
            dst,
            src,
            lambda: self.asm.shr_cl_b(self.context, dst.register),
            UNUSUAL_DATASET,
            lambda: self.asm.shr_b(self.context, dst.register, src.immediate),
            lambda: self.asm.shr_cl_b(self.context, dst.operand),
            lambda: self.asm.shr_b(self.context, dst.operand, src.immediate),
            lambda: self.asm.shr_cl_w(self.context, dst.register),
            UNUSUAL_DATASET,
            lambda: self.asm.shr_w(self.context, dst.register, src.immediate),
            lambda: self.asm.shr_cl_w(self.context, dst.operand),
            lambda: self.asm.shr_w(self.context, dst.operand, src.immediate),
            lambda: self.asm.shr_cl_dw(self.context, dst.register),
            UNUSUAL_DATASET,
            lambda: self.asm.shr_dw(self.context, dst.register, src.immediate),
            lambda: self.asm.shr_cl_dw(self.context, dst.operand),
            lambda: self.asm.shr_dw(self.context, dst.operand, src.immediate),
            lambda: self.asm.shr_cl_qw(self.context, dst.register),
            UNUSUAL_DATASET,
            lambda: self.asm.shr_qw(self.context, dst.register, src.immediate),
            lambda: self.asm.shr_cl_qw(self.context, dst.operand),
            lambda: self.asm.shr_qw(self.context, dst.operand, src.immediate),
        )

        return self.on_new_chain_item()

    def shl(self, dst: FukuType, src: FukuType) -> FukuAsmCtx:
        if (
            src.type == FukuT0Types.FUKU_T0_REGISTER
            and src.register.index != FukuRegisterIndex.INDEX_CX
        ):
            UNUSUAL_DATASET()

        self._fuku_assembler_command_2op_graph(
            dst,
            src,
            lambda: self.asm.shl_cl_b(self.context, dst.register),
            UNUSUAL_DATASET,
            lambda: self.asm.shl_b(self.context, dst.register, src.immediate),
            lambda: self.asm.shl_cl_b(self.context, dst.operand),
            lambda: self.asm.shl_b(self.context, dst.operand, src.immediate),
            lambda: self.asm.shl_cl_w(self.context, dst.register),
            UNUSUAL_DATASET,
            lambda: self.asm.shl_w(self.context, dst.register, src.immediate),
            lambda: self.asm.shl_cl_w(self.context, dst.operand),
            lambda: self.asm.shl_w(self.context, dst.operand, src.immediate),
            lambda: self.asm.shl_cl_dw(self.context, dst.register),
            UNUSUAL_DATASET,
            lambda: self.asm.shl_dw(self.context, dst.register, src.immediate),
            lambda: self.asm.shl_cl_dw(self.context, dst.operand),
            lambda: self.asm.shl_dw(self.context, dst.operand, src.immediate),
            lambda: self.asm.shl_cl_qw(self.context, dst.register),
            UNUSUAL_DATASET,
            lambda: self.asm.shl_qw(self.context, dst.register, src.immediate),
            lambda: self.asm.shl_cl_qw(self.context, dst.operand),
            lambda: self.asm.shl_qw(self.context, dst.operand, src.immediate),
        )

        return self.on_new_chain_item()

    def shrd(self, dst: FukuType, src: FukuType, shift: FukuType) -> FukuAsmCtx:
        if (
            shift.type == FukuT0Types.FUKU_T0_REGISTER
            and shift.register.index != FukuRegisterIndex.INDEX_CX
        ) or not (
            shift.type == FukuT0Types.FUKU_T0_REGISTER
            or shift.type == FukuT0Types.FUKU_T0_IMMEDIATE
        ):
            UNUSUAL_DATASET()

        shift_reg = shift.type == FukuT0Types.FUKU_T0_REGISTER

        self._fuku_assembler_command_2op_graph(
            dst,
            src,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            (lambda: self.asm.shrd_cl_w(self.context, dst.register, src.register))
            if shift_reg
            else (
                lambda: self.asm.shrd_w(
                    self.context, dst.register, src.register, shift.immediate
                )
            ),
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            (lambda: self.asm.shrd_cl_w(self.context, dst.operand, src.register))
            if shift_reg
            else (
                lambda: self.asm.shrd_w(
                    self.context, dst.operand, src.register, shift.immediate
                )
            ),
            UNUSUAL_DATASET,
            (lambda: self.asm.shrd_cl_dw(self.context, dst.register, src.register))
            if shift_reg
            else (
                lambda: self.asm.shrd_dw(
                    self.context, dst.register, src.register, shift.immediate
                )
            ),
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            (lambda: self.asm.shrd_cl_dw(self.context, dst.operand, src.register))
            if shift_reg
            else (
                lambda: self.asm.shrd_dw(
                    self.context, dst.operand, src.register, shift.immediate
                )
            ),
            UNUSUAL_DATASET,
            (lambda: self.asm.shrd_cl_qw(self.context, dst.register, src.register))
            if shift_reg
            else (
                lambda: self.asm.shrd_qw(
                    self.context, dst.register, src.register, shift.immediate
                )
            ),
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            (lambda: self.asm.shrd_cl_qw(self.context, dst.operand, src.register))
            if shift_reg
            else (
                lambda: self.asm.shrd_qw(
                    self.context, dst.operand, src.register, shift.immediate
                )
            ),
            UNUSUAL_DATASET,
        )

        return self.on_new_chain_item()

    def shld(self, dst: FukuType, src: FukuType, shift: FukuType) -> FukuAsmCtx:
        if (
            shift.type == FukuT0Types.FUKU_T0_REGISTER
            and shift.register.index != FukuRegisterIndex.INDEX_CX
        ) or not (
            shift.type == FukuT0Types.FUKU_T0_REGISTER
            or shift.type == FukuT0Types.FUKU_T0_IMMEDIATE
        ):
            UNUSUAL_DATASET()

        shift_reg = shift.type == FukuT0Types.FUKU_T0_REGISTER

        self._fuku_assembler_command_2op_graph(
            dst,
            src,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            (lambda: self.asm.shld_cl_w(self.context, dst.register, src.register))
            if shift_reg
            else (
                lambda: self.asm.shld_w(
                    self.context, dst.register, src.register, shift.immediate
                )
            ),
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            (lambda: self.asm.shld_cl_w(self.context, dst.operand, src.register))
            if shift_reg
            else (
                lambda: self.asm.shld_w(
                    self.context, dst.operand, src.register, shift.immediate
                )
            ),
            UNUSUAL_DATASET,
            (lambda: self.asm.shld_cl_dw(self.context, dst.register, src.register))
            if shift_reg
            else (
                lambda: self.asm.shld_dw(
                    self.context, dst.register, src.register, shift.immediate
                )
            ),
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            (lambda: self.asm.shld_cl_dw(self.context, dst.operand, src.register))
            if shift_reg
            else (
                lambda: self.asm.shld_dw(
                    self.context, dst.operand, src.register, shift.immediate
                )
            ),
            UNUSUAL_DATASET,
            (lambda: self.asm.shld_cl_qw(self.context, dst.register, src.register))
            if shift_reg
            else (
                lambda: self.asm.shld_qw(
                    self.context, dst.register, src.register, shift.immediate
                )
            ),
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            (lambda: self.asm.shld_cl_qw(self.context, dst.operand, src.register))
            if shift_reg
            else (
                lambda: self.asm.shld_qw(
                    self.context, dst.operand, src.register, shift.immediate
                )
            ),
            UNUSUAL_DATASET,
        )

        return self.on_new_chain_item()

    def ror(self, dst: FukuType, src: FukuType) -> FukuAsmCtx:
        if (
            src.type == FukuT0Types.FUKU_T0_REGISTER
            and src.register.index != FukuRegisterIndex.INDEX_CX
        ):
            UNUSUAL_DATASET()

        self._fuku_assembler_command_2op_graph(
            dst,
            src,
            lambda: self.asm.ror_cl_b(self.context, dst.register),
            UNUSUAL_DATASET,
            lambda: self.asm.ror_b(self.context, dst.register, src.immediate),
            lambda: self.asm.ror_cl_b(self.context, dst.operand),
            lambda: self.asm.ror_b(self.context, dst.operand, src.immediate),
            lambda: self.asm.ror_cl_w(self.context, dst.register),
            UNUSUAL_DATASET,
            lambda: self.asm.ror_w(self.context, dst.register, src.immediate),
            lambda: self.asm.ror_cl_w(self.context, dst.operand),
            lambda: self.asm.ror_w(self.context, dst.operand, src.immediate),
            lambda: self.asm.ror_cl_dw(self.context, dst.register),
            UNUSUAL_DATASET,
            lambda: self.asm.ror_dw(self.context, dst.register, src.immediate),
            lambda: self.asm.ror_cl_dw(self.context, dst.operand),
            lambda: self.asm.ror_dw(self.context, dst.operand, src.immediate),
            lambda: self.asm.ror_cl_qw(self.context, dst.register),
            UNUSUAL_DATASET,
            lambda: self.asm.ror_qw(self.context, dst.register, src.immediate),
            lambda: self.asm.ror_cl_qw(self.context, dst.operand),
            lambda: self.asm.ror_qw(self.context, dst.operand, src.immediate),
        )

        return self.on_new_chain_item()

    def rol(self, dst: FukuType, src: FukuType) -> FukuAsmCtx:
        if (
            src.type == FukuT0Types.FUKU_T0_REGISTER
            and src.register.index != FukuRegisterIndex.INDEX_CX
        ):
            UNUSUAL_DATASET()

        self._iced_assembler_command_2op_graph(
            dst,
            src,
            lambda: self.asm.rol_cl_b(self.context, dst.register),
            UNUSUAL_DATASET,
            lambda: self.asm.rol_b(self.context, dst.register, src.immediate),
            lambda: self.asm.rol_cl_b(self.context, dst.operand),
            lambda: self.asm.rol_b(self.context, dst.operand, src.immediate),
            lambda: self.asm.rol_cl_w(self.context, dst.register),
            UNUSUAL_DATASET,
            lambda: self.asm.rol_w(self.context, dst.register, src.immediate),
            lambda: self.asm.rol_cl_w(self.context, dst.operand),
            lambda: self.asm.rol_w(self.context, dst.operand, src.immediate),
            lambda: self.asm.rol_cl_dw(self.context, dst.register),
            UNUSUAL_DATASET,
            lambda: self.asm.rol_dw(self.context, dst.register, src.immediate),
            lambda: self.asm.rol_cl_dw(self.context, dst.operand),
            lambda: self.asm.rol_dw(self.context, dst.operand, src.immediate),
            lambda: self.asm.rol_cl_qw(self.context, dst.register),
            UNUSUAL_DATASET,
            lambda: self.asm.rol_qw(self.context, dst.register, src.immediate),
            lambda: self.asm.rol_cl_qw(self.context, dst.operand),
            lambda: self.asm.rol_qw(self.context, dst.operand, src.immediate),
        )

        return self.on_new_chain_item()

    def rcr(self, dst: FukuType, src: FukuType) -> FukuAsmCtx:
        if (
            src.type == FukuT0Types.FUKU_T0_REGISTER
            and src.register.index != FukuRegisterIndex.INDEX_CX
        ):
            UNUSUAL_DATASET()

        self._fuku_assembler_command_2op_graph(
            dst,
            src,
            lambda: self.asm.rcr_cl_b(self.context, dst.register),
            UNUSUAL_DATASET,
            lambda: self.asm.rcr_b(self.context, dst.register, src.immediate),
            lambda: self.asm.rcr_cl_b(self.context, dst.operand),
            lambda: self.asm.rcr_b(self.context, dst.operand, src.immediate),
            lambda: self.asm.rcr_cl_w(self.context, dst.register),
            UNUSUAL_DATASET,
            lambda: self.asm.rcr_w(self.context, dst.register, src.immediate),
            lambda: self.asm.rcr_cl_w(self.context, dst.operand),
            lambda: self.asm.rcr_w(self.context, dst.operand, src.immediate),
            lambda: self.asm.rcr_cl_dw(self.context, dst.register),
            UNUSUAL_DATASET,
            lambda: self.asm.rcr_dw(self.context, dst.register, src.immediate),
            lambda: self.asm.rcr_cl_dw(self.context, dst.operand),
            lambda: self.asm.rcr_dw(self.context, dst.operand, src.immediate),
            lambda: self.asm.rcr_cl_qw(self.context, dst.register),
            UNUSUAL_DATASET,
            lambda: self.asm.rcr_qw(self.context, dst.register, src.immediate),
            lambda: self.asm.rcr_cl_qw(self.context, dst.operand),
            lambda: self.asm.rcr_qw(self.context, dst.operand, src.immediate),
        )

        return self.on_new_chain_item()

    def rcl(self, dst: FukuType, src: FukuType) -> FukuAsmCtx:
        if (
            src.type == FukuT0Types.FUKU_T0_REGISTER
            and src.register.index != FukuRegisterIndex.INDEX_CX
        ):
            UNUSUAL_DATASET()

        self._fuku_assembler_command_2op_graph(
            dst,
            src,
            lambda: self.asm.rcl_cl_b(self.context, dst.register),
            UNUSUAL_DATASET,
            lambda: self.asm.rcl_b(self.context, dst.register, src.immediate),
            lambda: self.asm.rcl_cl_b(self.context, dst.operand),
            lambda: self.asm.rcl_b(self.context, dst.operand, src.immediate),
            lambda: self.asm.rcl_cl_w(self.context, dst.register),
            UNUSUAL_DATASET,
            lambda: self.asm.rcl_w(self.context, dst.register, src.immediate),
            lambda: self.asm.rcl_cl_w(self.context, dst.operand),
            lambda: self.asm.rcl_w(self.context, dst.operand, src.immediate),
            lambda: self.asm.rcl_cl_dw(self.context, dst.register),
            UNUSUAL_DATASET,
            lambda: self.asm.rcl_dw(self.context, dst.register, src.immediate),
            lambda: self.asm.rcl_cl_dw(self.context, dst.operand),
            lambda: self.asm.rcl_dw(self.context, dst.operand, src.immediate),
            lambda: self.asm.rcl_cl_qw(self.context, dst.register),
            UNUSUAL_DATASET,
            lambda: self.asm.rcl_qw(self.context, dst.register, src.immediate),
            lambda: self.asm.rcl_cl_qw(self.context, dst.operand),
            lambda: self.asm.rcl_qw(self.context, dst.operand, src.immediate),
        )

        return self.on_new_chain_item()

    # Bit and Byte Instructions
    def bt(self, dst: FukuType, src: FukuType) -> FukuAsmCtx:
        self._fuku_assembler_command_2op_graph(
            dst,
            src,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            lambda: self.asm.bt_w(self.context, dst.register, src.register),
            UNUSUAL_DATASET,
            lambda: self.asm.bt_w(self.context, dst.register, src.immediate),
            lambda: self.asm.bt_w(self.context, dst.operand, src.register),
            lambda: self.asm.bt_w(self.context, dst.operand, src.immediate),
            lambda: self.asm.bt_dw(self.context, dst.register, src.register),
            UNUSUAL_DATASET,
            lambda: self.asm.bt_dw(self.context, dst.register, src.immediate),
            lambda: self.asm.bt_dw(self.context, dst.operand, src.register),
            lambda: self.asm.bt_dw(self.context, dst.operand, src.immediate),
            lambda: self.asm.bt_qw(self.context, dst.register, src.register),
            UNUSUAL_DATASET,
            lambda: self.asm.bt_qw(self.context, dst.register, src.immediate),
            lambda: self.asm.bt_qw(self.context, dst.operand, src.register),
            lambda: self.asm.bt_qw(self.context, dst.operand, src.immediate),
        )

        return self.on_new_chain_item()

    def bts(self, dst: FukuType, src: FukuType) -> FukuAsmCtx:
        self._fuku_assembler_command_2op_graph(
            dst,
            src,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            lambda: self.asm.bts_w(self.context, dst.register, src.register),
            UNUSUAL_DATASET,
            lambda: self.asm.bts_w(self.context, dst.register, src.immediate),
            lambda: self.asm.bts_w(self.context, dst.operand, src.register),
            lambda: self.asm.bts_w(self.context, dst.operand, src.immediate),
            lambda: self.asm.bts_dw(self.context, dst.register, src.register),
            UNUSUAL_DATASET,
            lambda: self.asm.bts_dw(self.context, dst.register, src.immediate),
            lambda: self.asm.bts_dw(self.context, dst.operand, src.register),
            lambda: self.asm.bts_dw(self.context, dst.operand, src.immediate),
            lambda: self.asm.bts_qw(self.context, dst.register, src.register),
            UNUSUAL_DATASET,
            lambda: self.asm.bts_qw(self.context, dst.register, src.immediate),
            lambda: self.asm.bts_qw(self.context, dst.operand, src.register),
            lambda: self.asm.bts_qw(self.context, dst.operand, src.immediate),
        )

        return self.on_new_chain_item()

    def btr(self, dst: FukuType, src: FukuType) -> FukuAsmCtx:
        self._fuku_assembler_command_2op_graph(
            dst,
            src,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            lambda: self.asm.btr_w(self.context, dst.register, src.register),
            UNUSUAL_DATASET,
            lambda: self.asm.btr_w(self.context, dst.register, src.immediate),
            lambda: self.asm.btr_w(self.context, dst.operand, src.register),
            lambda: self.asm.btr_w(self.context, dst.operand, src.immediate),
            lambda: self.asm.btr_dw(self.context, dst.register, src.register),
            UNUSUAL_DATASET,
            lambda: self.asm.btr_dw(self.context, dst.register, src.immediate),
            lambda: self.asm.btr_dw(self.context, dst.operand, src.register),
            lambda: self.asm.btr_dw(self.context, dst.operand, src.immediate),
            lambda: self.asm.btr_qw(self.context, dst.register, src.register),
            UNUSUAL_DATASET,
            lambda: self.asm.btr_qw(self.context, dst.register, src.immediate),
            lambda: self.asm.btr_qw(self.context, dst.operand, src.register),
            lambda: self.asm.btr_qw(self.context, dst.operand, src.immediate),
        )

        return self.on_new_chain_item()

    def btc(self, dst: FukuType, src: FukuType) -> FukuAsmCtx:
        self._fuku_assembler_command_2op_graph(
            dst,
            src,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            lambda: self.asm.btc_w(self.context, dst.register, src.register),
            UNUSUAL_DATASET,
            lambda: self.asm.btc_w(self.context, dst.register, src.immediate),
            lambda: self.asm.btc_w(self.context, dst.operand, src.register),
            lambda: self.asm.btc_w(self.context, dst.operand, src.immediate),
            lambda: self.asm.btc_dw(self.context, dst.register, src.register),
            UNUSUAL_DATASET,
            lambda: self.asm.btc_dw(self.context, dst.register, src.immediate),
            lambda: self.asm.btc_dw(self.context, dst.operand, src.register),
            lambda: self.asm.btc_dw(self.context, dst.operand, src.immediate),
            lambda: self.asm.btc_qw(self.context, dst.register, src.register),
            UNUSUAL_DATASET,
            lambda: self.asm.btc_qw(self.context, dst.register, src.immediate),
            lambda: self.asm.btc_qw(self.context, dst.operand, src.register),
            lambda: self.asm.btc_qw(self.context, dst.operand, src.immediate),
        )

        return self.on_new_chain_item()

    def setcc(self, cond: FukuCondition, dst: FukuType) -> FukuAsmCtx:
        self._fuku_assembler_command_1op_graph(
            dst,
            lambda: self.asm.setcc(self.context, cond, dst.register),
            lambda: self.asm.setcc(self.context, cond, dst.operand),
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
        )

        return self.on_new_chain_item()

    def test(self, dst: FukuType, src: FukuType) -> FukuAsmCtx:
        self._fuku_assembler_command_2op_graph(
            dst,
            src,
            lambda: self.asm.test_b(self.context, dst.register, src.register),
            UNUSUAL_DATASET,
            lambda: self.asm.test_b(self.context, dst.register, src.immediate),
            lambda: self.asm.test_b(self.context, dst.operand, src.register),
            lambda: self.asm.test_b(self.context, dst.operand, src.immediate),
            lambda: self.asm.test_w(self.context, dst.register, src.register),
            UNUSUAL_DATASET,
            lambda: self.asm.test_w(self.context, dst.register, src.immediate),
            lambda: self.asm.test_w(self.context, dst.operand, src.register),
            lambda: self.asm.test_w(self.context, dst.operand, src.immediate),
            lambda: self.asm.test_dw(self.context, dst.register, src.register),
            UNUSUAL_DATASET,
            lambda: self.asm.test_dw(self.context, dst.register, src.immediate),
            lambda: self.asm.test_dw(self.context, dst.operand, src.register),
            lambda: self.asm.test_dw(self.context, dst.operand, src.immediate),
            lambda: self.asm.test_qw(self.context, dst.register, src.register),
            UNUSUAL_DATASET,
            lambda: self.asm.test_qw(self.context, dst.register, src.immediate),
            lambda: self.asm.test_qw(self.context, dst.operand, src.register),
            lambda: self.asm.test_qw(self.context, dst.operand, src.immediate),
        )

        return self.on_new_chain_item()

    def popcnt(self, dst: FukuType, src: FukuType) -> FukuAsmCtx:
        self._fuku_assembler_command_2op_graph(
            dst,
            src,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            lambda: self.asm.popcnt_w(self.context, dst.register, src.register),
            lambda: self.asm.popcnt_w(self.context, dst.register, dst.operand),
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            lambda: self.asm.popcnt_dw(self.context, dst.register, src.register),
            lambda: self.asm.popcnt_dw(self.context, dst.register, dst.operand),
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            lambda: self.asm.popcnt_qw(self.context, dst.register, src.register),
            lambda: self.asm.popcnt_qw(self.context, dst.register, dst.operand),
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
        )

        return self.on_new_chain_item()

    # Control Transfer Instructions
    def jmp(self, src: FukuType) -> FukuAsmCtx:
        self._fuku_assembler_command_1op_graph(
            src,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            lambda: self.asm.jmp(self.context, src.register),
            lambda: self.asm.jmp(self.context, src.operand),
            lambda: self.asm.jmp(self.context, src.immediate),
            lambda: self.asm.jmp(self.context, src.register),
            lambda: self.asm.jmp(self.context, src.operand),
            lambda: self.asm.jmp(self.context, src.immediate),
        )

        return self.on_new_chain_item()

    def jcc(self, cond: FukuCondition, src: FukuType) -> FukuAsmCtx:
        self._fuku_assembler_command_1op_graph(
            src,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            lambda: self.asm.jcc(self.context, cond, src.immediate),
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            lambda: self.asm.jcc(self.context, cond, src.immediate),
        )

        return self.on_new_chain_item()

    def call(self, src: FukuType) -> FukuAsmCtx:
        self._fuku_assembler_command_1op_graph(
            src,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            lambda: self.asm.call(self.context, src.register),
            lambda: self.asm.call(self.context, src.operand),
            lambda: self.asm.call(self.context, src.immediate),
            lambda: self.asm.call(self.context, src.register),
            lambda: self.asm.call(self.context, src.operand),
            lambda: self.asm.call(self.context, src.immediate),
        )

        return self.on_new_chain_item()

    def ret(self, src: FukuType) -> FukuAsmCtx:
        self._fuku_assembler_command_1op_graph(
            src,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            (lambda: self.asm.ret(self.context, src.immediate))
            if src.immediate.immediate16
            else (lambda: self.asm.ret(self.context)),
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            (lambda: self.asm.ret(self.context, src.immediate))
            if src.immediate.immediate16
            else (lambda: self.asm.ret(self.context)),
        )

        return self.on_new_chain_item()

    def int3(self) -> FukuAsmCtx:
        self.asm.int3(self.context)
        return self.on_new_chain_item()

    def enter(self, size: FukuType, nesting_level: FukuType) -> FukuAsmCtx:
        if (
            size.type != FukuT0Types.FUKU_T0_IMMEDIATE
            or nesting_level.type != FukuT0Types.FUKU_T0_IMMEDIATE
        ):
            UNUSUAL_DATASET()

        self.on_emit()
        self.asm.enter(self.context, size.immediate, nesting_level.immediate.immediate8)

        return self.on_new_chain_item()

    def leave(self) -> FukuAsmCtx:
        self.asm.leave(self.context)
        return self.on_new_chain_item()

    # String Instructions
    def outsb(self) -> FukuAsmCtx:
        self.on_emit()
        self.asm.outsb(self.context)
        return self.on_new_chain_item()

    def outsw(self) -> FukuAsmCtx:
        self.on_emit()
        self.asm.outsw(self.context)
        return self.on_new_chain_item()

    def outsd(self) -> FukuAsmCtx:
        self.on_emit()
        self.asm.outsd(self.context)
        return self.on_new_chain_item()

    def movsb(self) -> FukuAsmCtx:
        self.on_emit()
        self.asm.movsb(self.context)
        return self.on_new_chain_item()

    def movsw(self) -> FukuAsmCtx:
        self.on_emit()
        self.asm.movsw(self.context)
        return self.on_new_chain_item()

    def movsd(self) -> FukuAsmCtx:
        self.on_emit()
        self.asm.movsd(self.context)
        return self.on_new_chain_item()

    def movsq(self) -> FukuAsmCtx:
        self.on_emit()
        self.asm.movsq(self.context)
        return self.on_new_chain_item()

    def cmpsb(self) -> FukuAsmCtx:
        self.on_emit()
        self.asm.cmpsb(self.context)
        return self.on_new_chain_item()

    def cmpsw(self) -> FukuAsmCtx:
        self.on_emit()
        self.asm.cmpsw(self.context)
        return self.on_new_chain_item()

    def cmpsd(self) -> FukuAsmCtx:
        self.on_emit()
        self.asm.cmpsd(self.context)
        return self.on_new_chain_item()

    def cmpsq(self) -> FukuAsmCtx:
        self.on_emit()
        self.asm.cmpsq(self.context)
        return self.on_new_chain_item()

    def scasb(self) -> FukuAsmCtx:
        self.on_emit()
        self.asm.scasb(self.context)
        return self.on_new_chain_item()

    def scasw(self) -> FukuAsmCtx:
        self.on_emit()
        self.asm.scasw(self.context)
        return self.on_new_chain_item()

    def scasd(self) -> FukuAsmCtx:
        self.on_emit()
        self.asm.scasd(self.context)
        return self.on_new_chain_item()

    def scasq(self) -> FukuAsmCtx:
        self.on_emit()
        self.asm.scasq(self.context)
        return self.on_new_chain_item()

    def lodsb(self) -> FukuAsmCtx:
        self.on_emit()
        self.asm.lodsb(self.context)
        return self.on_new_chain_item()

    def lodsw(self) -> FukuAsmCtx:
        self.on_emit()
        self.asm.lodsw(self.context)
        return self.on_new_chain_item()

    def lodsd(self) -> FukuAsmCtx:
        self.on_emit()
        self.asm.lodsd(self.context)
        return self.on_new_chain_item()

    def lodsq(self) -> FukuAsmCtx:
        self.on_emit()
        self.asm.lodsq(self.context)
        return self.on_new_chain_item()

    def stosb(self) -> FukuAsmCtx:
        self.on_emit()
        self.asm.stosb(self.context)
        return self.on_new_chain_item()

    def stosw(self) -> FukuAsmCtx:
        self.on_emit()
        self.asm.stosw(self.context)
        return self.on_new_chain_item()

    def stosd(self) -> FukuAsmCtx:
        self.on_emit()
        self.asm.stosd(self.context)
        return self.on_new_chain_item()

    def stosq(self) -> FukuAsmCtx:
        self.on_emit()
        self.asm.stosq(self.context)
        return self.on_new_chain_item()

    def stc(self) -> FukuAsmCtx:
        self.on_emit()
        self.asm.stc(self.context)
        return self.on_new_chain_item()

    def clc(self) -> FukuAsmCtx:
        self.on_emit()
        self.asm.clc(self.context)
        return self.on_new_chain_item()

    def cmc(self) -> FukuAsmCtx:
        self.on_emit()
        self.asm.cmc(self.context)
        return self.on_new_chain_item()

    def cld(self) -> FukuAsmCtx:
        self.on_emit()
        self.asm.cld(self.context)
        return self.on_new_chain_item()

    def std(self) -> FukuAsmCtx:
        self.on_emit()
        self.asm.std(self.context)
        return self.on_new_chain_item()

    def lahf(self) -> FukuAsmCtx:
        self.on_emit()
        self.asm.lahf(self.context)
        return self.on_new_chain_item()

    def sahf(self) -> FukuAsmCtx:
        self.on_emit()
        self.asm.sahf(self.context)
        return self.on_new_chain_item()

    def pusha(self) -> FukuAsmCtx:
        self.on_emit()
        self.asm.pusha(self.context)
        return self.on_new_chain_item()

    def pushad(self) -> FukuAsmCtx:
        self.on_emit()
        self.asm.pushad(self.context)
        return self.on_new_chain_item()

    def popa(self) -> FukuAsmCtx:
        self.on_emit()
        self.asm.popa(self.context)
        return self.on_new_chain_item()

    def popad(self) -> FukuAsmCtx:
        self.on_emit()
        self.asm.popad(self.context)
        return self.on_new_chain_item()

    def pushf(self) -> FukuAsmCtx:
        self.on_emit()
        self.asm.pushf(self.context)
        return self.on_new_chain_item()

    def pushfd(self) -> FukuAsmCtx:
        self.on_emit()
        self.asm.pushfd(self.context)
        return self.on_new_chain_item()

    def pushfq(self) -> FukuAsmCtx:
        self.on_emit()
        self.asm.pushfq(self.context)
        return self.on_new_chain_item()

    def popf(self) -> FukuAsmCtx:
        self.on_emit()
        self.asm.popf(self.context)
        return self.on_new_chain_item()

    def popfd(self) -> FukuAsmCtx:
        self.on_emit()
        self.asm.popfd(self.context)
        return self.on_new_chain_item()

    def popfq(self) -> FukuAsmCtx:
        self.on_emit()
        self.asm.popfq(self.context)
        return self.on_new_chain_item()

    # Miscellaneous Instructions
    def lea(self, dst: FukuType, src: FukuType) -> FukuAsmCtx:
        self._fuku_assembler_command_2op_graph(
            dst,
            src,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            lambda: self.asm.lea_w(self.context, dst.register, src.operand),
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            lambda: self.asm.lea_dw(self.context, dst.register, src.operand),
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            lambda: self.asm.lea_qw(self.context, dst.register, src.operand),
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
        )

        return self.on_new_chain_item()

    def nop(self, size: int = None) -> FukuAsmCtx:
        self.on_emit()
        self.asm.nop(self.context, size)
        return self.on_new_chain_item()

    def ud2(self) -> FukuAsmCtx:
        self.on_emit()
        self.asm.ud2(self.context)
        return self.on_new_chain_item()

    def cpuid(self) -> FukuAsmCtx:
        self.on_emit()
        self.asm.cpuid(self.context)
        return self.on_new_chain_item()

    # Random Number Generator Instructions
    def rdrand(self, dst: FukuType) -> FukuAsmCtx:
        self._fuku_assembler_command_1op_graph(
            dst,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            lambda: self.asm.rdrand_w(self.context, dst.register),
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            lambda: self.asm.rdrand_dw(self.context, dst.register),
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            lambda: self.asm.rdrand_qw(self.context, dst.register),
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
        )

        return self.on_new_chain_item()

    def rdseed(self, dst: FukuType) -> FukuAsmCtx:
        self._fuku_assembler_command_1op_graph(
            dst,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            lambda: self.asm.rdseed_w(self.context, dst.register),
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            lambda: self.asm.rdseed_dw(self.context, dst.register),
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
            lambda: self.asm.rdseed_qw(self.context, dst.register),
            UNUSUAL_DATASET,
            UNUSUAL_DATASET,
        )

        return self.on_new_chain_item()

    # SYSTEM INSTRUCTIONS
    def hlt(self) -> FukuAsmCtx:
        self.on_emit()
        self.asm.hlt(self.context)
        return self.on_new_chain_item()

    def rdtsc(self) -> FukuAsmCtx:
        self.on_emit()
        self.asm.rdtsc(self.context)
        return self.on_new_chain_item()

    def lfence(self) -> FukuAsmCtx:
        self.on_emit()
        self.asm.lfence(self.context)
        return self.on_new_chain_item()
