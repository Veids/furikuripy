from enum import Enum
import inspect
import itertools

from pydantic import BaseModel, ConfigDict
from typing import Callable, ClassVar, Optional, Tuple
from iced_x86 import Code, Instruction, BlockEncoder, Register
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64, x86_const

from furikuripy.common import rng
from furikuripy.x86.fuku_asm_ctx import FukuAsmCtx
from furikuripy.x86.fuku_immediate import FukuImmediate
from furikuripy.x86.fuku_operand import FukuMemOperandType, FukuOperand
from furikuripy.x86.fuku_register import (
    FukuRegister,
    FukuRegisterIndex,
)
from furikuripy.x86.inst_tables import InstProp
from furikuripy.x86.misc import FukuCondition, FukuToCapConvertType
from furikuripy.x86.fuku_register_math_tables import ADI_FL_JCC


cs = Cs(CS_ARCH_X86, CS_MODE_64)
cs.detail = True


class PostfixEnum(Enum):
    b = 8
    w = 16
    dw = 32
    qw = 64


class PostfixedWrapper(BaseModel):
    postfix: str
    wrapper: Callable


def gen_iced_ins(ctx, ins):
    encoder = BlockEncoder(64)
    encoder.add(ins)
    opcode = encoder.encode(0x0)

    ins = next(cs.disasm(opcode, 0))
    ctx.displacment_offset = ins.disp_offset
    ctx.bytecode = bytearray(opcode)


def parts_for(ctx, obj, size: int, max_imm_size: int = 64) -> list[str]:
    if isinstance(obj, FukuRegister):
        return [f"R{size}", f"RM{size}"]
    elif isinstance(obj, FukuOperand):
        return [f"RM{size}"]
    elif isinstance(obj, FukuImmediate):
        return [obj.to_iced_code(ctx.is_used_short_disp, min(size, max_imm_size))]
    else:
        raise TypeError(obj)


class BaseBuilder(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    name: str
    inst: InstProp
    parameters: list[inspect.Parameter] = list()
    exclude_inst: list[str] = list()
    exclude_postfix: list[str] = list()
    code_resolver: Optional[Callable] = None

    cl: bool = False
    postfix_modifier: str = ""
    name_postfix: str = ""
    max_imm_size: int = 64

    # registry of name → builder subclass
    _registry: ClassVar[dict[str, type["BaseBuilder"]]] = {}

    @classmethod
    def register(cls, mnemonics: list[str]):
        def decorator(subcls: type["BaseBuilder"]):
            for mnemonic in mnemonics:
                cls._registry[mnemonic] = subcls
            return subcls

        return decorator

    def build(self) -> tuple[str, list[PostfixedWrapper]]:
        self._get_default_params()
        self._gen_inst_params()

        # pick the right subclass (or fallback to GenericBuilder)
        subcls = self._registry.get(self.name, GenericBuilder)
        return subcls(**self.model_dump())._build()

    def _build(self) -> Tuple[str, list[PostfixedWrapper]]:
        """Override in subclasses to implement per-mnemonic logic."""
        raise NotImplementedError

    def _gen_inst_params(self):
        for param_name, param_type in self.inst.ops.items():
            self.parameters.append(
                inspect.Parameter(
                    param_name,
                    inspect.Parameter.POSITIONAL_OR_KEYWORD,
                    annotation=param_type,
                )
            )

    def _get_default_params(self):
        self.parameters.append(
            inspect.Parameter(
                "self", inspect.Parameter.POSITIONAL_ONLY, annotation="FukuAsmBody"
            )
        )
        self.parameters.append(
            inspect.Parameter(
                "ctx",
                inspect.Parameter.POSITIONAL_OR_KEYWORD,
                annotation=FukuAsmCtx,
            )
        )

    def _gen_iced_code_str(self, *args) -> str:
        parts = [self.name.upper()]
        parts += list(args)

        if self.cl:
            parts.append("CL")

        return "_".join(parts)

    def _get_iced_code_from_posibilities(self, posibilities) -> int:
        if len(posibilities) == 1:
            return getattr(Code, posibilities[0])
        else:
            return getattr(Code, rng.choice(posibilities))

    def _choose_from_posibilities(self, *args):
        posibilities = []
        for x in itertools.product(*args):
            code_str = self.name.upper() + self.name_postfix + "_" + "_".join(x)

            if self.cl:
                code_str += "_CL"

            if code_str in self.exclude_inst or not hasattr(Code, code_str):
                continue

            posibilities.append(code_str)

        return self._get_iced_code_from_posibilities(posibilities)

    def resolve_code(self, ctx, size, ops: Tuple):
        if self.code_resolver:
            return getattr(Code, self.code_resolver(ctx, self.name, *ops, size))

        if len(ops) == 0:
            code_str = self._gen_iced_code_str()
            return getattr(Code, code_str)

        posibilities = []
        for op in ops:
            parts = parts_for(ctx, op, size, min(size, self.max_imm_size))
            posibilities.append(parts)

        return self._choose_from_posibilities(*posibilities)

    def _get_iced_create_inst(self, *args) -> Callable:
        s = ["create"] + [arg.to_iced_name() for arg in args]

        if self.cl:
            s.append("reg")

        s = "_".join(s)

        return getattr(Instruction, s)

    def call_iced_create_inst(self, code, *ops):
        fn = self._get_iced_create_inst(*ops)
        fn_arguments = [op.to_iced() for op in ops]

        if self.cl:
            fn_arguments.append(Register.CL)

        return fn(code, *fn_arguments)

    def gen_default_postfix(self, wrapper: Callable) -> list[PostfixedWrapper]:
        res = []
        for p in PostfixEnum:
            if p.name in self.exclude_postfix:
                continue

            p_str = p.name
            if self.cl:
                p_str = f"cl_{p_str}"

            res.append(PostfixedWrapper(postfix=p_str, wrapper=wrapper(p.value)))
        return res

    def _deduce_postfix(self, wrapper) -> list[PostfixedWrapper]:
        if len(self.inst.ops):
            return self.gen_default_postfix(wrapper)
        else:
            return [PostfixedWrapper(postfix="", wrapper=wrapper(0))]


class GenericBuilder(BaseBuilder):
    def _build(self) -> Tuple[str, list[PostfixedWrapper]]:
        def wrapper(size: int):
            fn_signature = inspect.Signature(self.parameters)

            def fn(*args):
                ctx = args[1]
                ops = args[2:]

                ctx.clear()

                code = self.resolve_code(ctx, size, ops)
                ins = self.call_iced_create_inst(code, *ops)
                gen_iced_ins(ctx, ins)
                ctx.gen_func_return(self.inst.capstone_code, self.inst.cap_eflags)

            fn.__signature__ = fn_signature
            return fn

        return self.name, self._deduce_postfix(wrapper)


@BaseBuilder.register(["mov"])
class MovBuilder(BaseBuilder):
    def _build(self) -> Tuple[str, list[PostfixedWrapper]]:
        eax_mapping = {
            8: {
                "code_reg_op": Code.MOV_AL_MOFFS8,
                "code_op_reg": Code.MOV_MOFFS8_AL,
                "op_imm_size": 8,
            },
            16: {
                "code_reg_op": Code.MOV_AX_MOFFS16,
                "code_op_reg": Code.MOV_MOFFS16_AX,
                "op_imm_size": 16,
            },
            32: {
                "code_reg_op": Code.MOV_EAX_MOFFS32,
                "code_op_reg": Code.MOV_MOFFS32_EAX,
                "op_imm_size": 32,
            },
            64: {
                "code_reg_op": Code.MOV_RAX_MOFFS64,
                "code_op_reg": Code.MOV_MOFFS64_RAX,
                "op_imm_size": 32,
            },
        }

        def wrapper(size: int):
            fn_signature = inspect.Signature(self.parameters)

            def fn(*args):
                ctx = args[1]
                ops = args[2:]
                dst = ops[0]
                src = ops[1]

                ctx.clear()

                reg_dst = isinstance(dst, FukuRegister)
                reg_src = isinstance(src, FukuRegister)
                opnd_dst = isinstance(dst, FukuOperand)
                opnd_src = isinstance(src, FukuOperand)
                imm_src = isinstance(src, FukuImmediate)
                disp_only = (
                    lambda o: o.type == FukuMemOperandType.FUKU_MEM_OPERAND_DISP_ONLY
                )

                # A) “register ↔ operand” pairing:
                is_reg_mem_pair = (reg_dst and opnd_src) or (opnd_dst and reg_src)

                # B) Is one side EAX, the other a displacement‐only memory operand?
                is_eax_reg = (
                    lambda o: isinstance(o, FukuRegister)
                    and o.reg.index == FukuRegisterIndex.INDEX_AX
                )
                uses_eax_disp = (is_eax_reg(dst) and opnd_src and disp_only(src)) or (
                    is_eax_reg(src) and opnd_dst and disp_only(dst)
                )

                if is_reg_mem_pair and ctx.is_used_short_eax and uses_eax_disp:
                    # If the register side is EAX, pick code_reg_op, else code_op_reg
                    if is_eax_reg(dst):
                        code = eax_mapping[size]["code_reg_op"]
                    else:
                        code = eax_mapping[size]["code_op_reg"]

                elif opnd_dst and reg_src:
                    # memory ← register
                    code = getattr(Code, f"{self.name.upper()}_RM{size}_R{size}")

                elif opnd_dst and imm_src:
                    # memory ← immediate
                    imm_sz = eax_mapping[size]["op_imm_size"]
                    code = getattr(Code, f"{self.name.upper()}_RM{size}_IMM{imm_sz}")

                else:
                    # fallback to generic
                    code = self.resolve_code(ctx, size, ops)

                ins = self.call_iced_create_inst(code, *ops)
                gen_iced_ins(ctx, ins)

                if isinstance(dst, FukuRegister) and isinstance(src, FukuImmediate):
                    ctx.gen_func_return(x86_const.X86_INS_MOVABS, 0)
                else:
                    ctx.gen_func_return(x86_const.X86_INS_MOV, 0)

            fn.__signature__ = fn_signature
            return fn

        return self.name, self._deduce_postfix(wrapper)


@BaseBuilder.register(["test"])
class TestBuilder(BaseBuilder):
    def _build(self) -> Tuple[str, list[PostfixedWrapper]]:
        def wrapper(size: int):
            fn_signature = inspect.Signature(self.parameters)

            def fn(*args):
                ctx = args[1]
                ops = args[2:]

                ctx.clear()

                if (
                    isinstance(ops[0], FukuRegister)
                    and isinstance(ops[1], FukuImmediate)
                    and ctx.is_used_short_eax
                    and ops[0].reg.index == FukuRegisterIndex.INDEX_AX
                ):
                    code_str = f"TEST_{ops[0].to_iced_str()}_IMM{size}"
                    code = getattr(Code, code_str)
                else:
                    code = self.resolve_code(ctx, size, ops)

                ins = self.call_iced_create_inst(code, *ops)
                gen_iced_ins(ctx, ins)
                ctx.gen_func_return(self.inst.capstone_code, self.inst.cap_eflags)

            fn.__signature__ = fn_signature
            return fn

        return self.name, self._deduce_postfix(wrapper)


@BaseBuilder.register(["outs", "movs", "cmps", "stos", "lods", "scas"])
class StringBuilder(BaseBuilder):
    mapping: ClassVar[dict[str, dict[int, str]]] = {
        "outs": {
            8: "B_DX_M8",
            16: "W_DX_M16",
            32: "D_DX_M32",
        },
        "movs": {
            8: "B_M8_M8",
            16: "W_M16_M16",
            32: "D_M32_M32",
            64: "Q_M64_M64",
        },
        "cmps": {
            8: "B_M8_M8",
            16: "W_M16_M16",
            32: "D_M32_M32",
            64: "Q_M64_M64",
        },
        "stos": {
            8: "B_M8_AL",
            16: "W_M16_AX",
            32: "D_M32_EAX",
            64: "Q_M64_RAX",
        },
        "lods": {
            8: "B_AL_M8",
            16: "W_AX_M16",
            32: "D_EAX_M32",
            64: "Q_RAX_M64",
        },
        "scas": {
            8: "B_AL_M8",
            16: "W_AX_M16",
            32: "D_EAX_M32",
            64: "Q_RAX_M64",
        },
    }

    def _get_capstone_code(self, size) -> int:
        postfix_stripped = PostfixEnum(size).name[:1].upper()
        name = self.name.upper()
        return getattr(x86_const, f"X86_INS_{name}{postfix_stripped}")

    def _build(self) -> Tuple[str, list[PostfixedWrapper]]:
        def wrapper(size: int):
            fn_signature = inspect.Signature(self.parameters)

            def fn(*args):
                ctx = args[1]
                ctx.clear()

                code = getattr(
                    Code, f"{self.name.upper()}{self.mapping[self.name][size]}"
                )
                ins = Instruction.create(code)
                gen_iced_ins(ctx, ins)

                ctx.gen_func_return(self._get_capstone_code(size), self.inst.cap_eflags)

            fn.__signature__ = fn_signature
            return fn

        return self.name, self._deduce_postfix(wrapper)


@BaseBuilder.register(["cmovcc"])
class CmovConditionBuilder(BaseBuilder):
    handler_str: ClassVar[str] = "cmovcc"
    type_str: ClassVar[str] = "CMOV"
    type: ClassVar[FukuToCapConvertType] = FukuToCapConvertType.CMOVCC

    def _build(self) -> Tuple[str, list[PostfixedWrapper]]:
        def wrapper(size: int):
            fn_signature = inspect.Signature(self.parameters)

            def fn(*args):
                ctx = args[1]
                ops = args[2:]
                cond: FukuCondition = ops[0]
                ops = ops[1:]

                ctx.clear()

                self.name = self.__class__.type_str + cond.to_iced_cc()
                code = self.resolve_code(ctx, size, ops)
                ins = self.call_iced_create_inst(code, *ops)
                gen_iced_ins(ctx, ins)
                ctx.gen_func_return(
                    cond.to_capstone_cc(self.__class__.type), ADI_FL_JCC[cond.value]
                )
                self.name = self.__class__.handler_str

            fn.__signature__ = fn_signature
            return fn

        return self.name, self.gen_default_postfix(wrapper)


@BaseBuilder.register(["setcc"])
class SetConditionBuilder(ConditionBuilder):
    handler_str: ClassVar[str] = "setcc"
    type_str: ClassVar[str] = "SET"
    type: ClassVar[FukuToCapConvertType] = FukuToCapConvertType.SETCC
