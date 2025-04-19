from enum import Enum
import inspect
import itertools

from pydantic import BaseModel, ConfigDict
from typing import Callable, Optional, Tuple
from iced_x86 import Code, Instruction, BlockEncoder, Register
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64

from furikuripy.common import rng
from furikuripy.x86.fuku_asm_ctx import FukuAsmCtx
from furikuripy.x86.fuku_immediate import FukuImmediate
from furikuripy.x86.fuku_operand import FukuOperand
from furikuripy.x86.fuku_register import FukuRegister
from furikuripy.x86.inst_tables import InstProp


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


def build_code_left_part(t, size: int) -> str:
    if isinstance(t, FukuRegister):
        return f"R{size}"
    elif isinstance(t, FukuOperand):
        return f"RM{size}"
    else:
        raise Exception("Unknown")


def build_code_right_part(ctx, t, size: int) -> str:
    if isinstance(t, FukuRegister):
        return f"RM{size}"
    elif isinstance(t, FukuOperand):
        return f"RM{size}"
    elif isinstance(t, FukuImmediate):
        return t.to_iced_code(ctx.is_used_short_disp, size)
    else:
        raise Exception("Unimplemented")


class IcedBuilder(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    name: str
    inst: InstProp
    parameters: list[inspect.Parameter] = list()
    exclude_inst: list[str] = list()
    exclude_postfix: list[str] = list()
    code_resolver: Optional[Callable] = None

    cl: bool = False
    postfix_modifier: str = ""
    max_imm_size: int = 64

    def model_post_init(self, _):
        self._get_default_params()
        self._gen_inst_params()

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

    def ops(self, **fn_param_types):
        for param_name, param_type in fn_param_types.items():
            self.parameters.append(
                inspect.Parameter(
                    param_name,
                    inspect.Parameter.POSITIONAL_OR_KEYWORD,
                    annotation=param_type,
                )
            )
        return self

    def _get_iced_code(self, *args) -> int:
        code_str = self._gen_iced_code_str(*args)
        return getattr(Code, code_str)

    def _has_iced_code(self, *args) -> bool:
        code_str = self._gen_iced_code_str(*args)
        return hasattr(Code, code_str)

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

    def _get_iced_code_one_op(self, ctx, size: int, src) -> int:
        if isinstance(src, FukuRegister):
            ls = [f"R{size}", f"RM{size}"]
            posibilities = [
                self._gen_iced_code_str(l) for l in ls if self._has_iced_code(l)
            ]
            posibilities = [pos for pos in posibilities if pos not in self.exclude_inst]

            return self._get_iced_code_from_posibilities(posibilities)
        else:
            l = build_code_right_part(ctx, src, size)

        return self._get_iced_code(l)

    def _get_iced_code_two_op(self, ctx, size: int, dst, src):
        l = r = ""
        if isinstance(src, FukuImmediate):
            l = f"RM{size}"
            r = build_code_right_part(ctx, src, min(size, self.max_imm_size))
        elif isinstance(dst, FukuRegister) and isinstance(src, FukuRegister):
            ls = [f"R{size}", f"RM{size}"]
            rs = ls.copy()
            posibilities = []
            for l, r in itertools.product(ls, rs):
                if self._has_iced_code(l, r):
                    posibilities.append(self._gen_iced_code_str(l, r))

            return self._get_iced_code_from_posibilities(posibilities)
        else:
            l = build_code_left_part(dst, size)
            r = build_code_right_part(ctx, src, size)

        return self._get_iced_code(l, r)

    def _get_iced_code_three_op(self, ctx, size: int, dst, src, imm):
        l = build_code_left_part(dst, size)
        r = build_code_right_part(ctx, src, size)
        i = build_code_right_part(ctx, imm, size)
        return self._get_iced_code(l, r, i)

    def _get_iced_code_no_ops(self, _, size: int):
        return self._get_iced_code()

    def resolve_code(self, ctx, size, ops: Tuple):
        if self.code_resolver:
            return getattr(Code, self.code_resolver(ctx, self.name, *ops, size))
        else:
            resolve_map = {
                0: self._get_iced_code_no_ops,
                1: self._get_iced_code_one_op,
                2: self._get_iced_code_two_op,
                3: self._get_iced_code_three_op,
            }
            return resolve_map[len(ops)](ctx, size, *ops)

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

    def build(self) -> Tuple[str, list[PostfixedWrapper]]:
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

        if len(self.inst.ops):
            return self.name, self.gen_default_postfix(wrapper)
        else:
            return self.name, [PostfixedWrapper(postfix="", wrapper=wrapper(0))]
