import itertools

from enum import Enum
from typing import Callable, Optional
from capstone import x86_const, Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
from iced_x86 import Code, Instruction
from pydantic import BaseModel


from furikuripy.common import rng
from furikuripy.x86.inst_tables import INST_PROPS
from furikuripy.x86.misc import FukuCondition, FukuToCapConvertType
from furikuripy.x86.iced_builder import BaseBuilder, gen_iced_ins
from furikuripy.x86.fuku_asm_ctx import FukuAsmCtx
from furikuripy.x86.fuku_immediate import FukuImmediate
from furikuripy.x86.fuku_register import FukuRegister, FukuRegisterEnum
from furikuripy.x86.fuku_operand import FukuOperand, FukuPrefix
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


def gen_default_postfix(
    wrapper: Callable, modifier: str = "", exclude: list[str] = []
) -> list[PostfixedWrapper]:
    return [
        PostfixedWrapper(postfix=f"{modifier}{p.name}", wrapper=wrapper(p.value))
        for p in PostfixEnum
        if p.name not in exclude
    ]


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


def get_iced_code_two_op(
    ctx, name: str, dst, src, size, postfix: str = "", max_imm_size=64
):
    name = name.upper()
    l = r = ""
    if isinstance(src, FukuImmediate):
        l = f"RM{size}"
        r = build_code_right_part(ctx, src, min(size, max_imm_size))
    elif isinstance(dst, FukuRegister) and isinstance(src, FukuRegister):
        ls = [f"R{size}", f"RM{size}"]
        rs = ls.copy()
        posibilities = []
        for l, r in itertools.product(ls, rs):
            code_str = f"{name}_{l}_{r}{postfix}"
            if hasattr(Code, code_str):
                posibilities.append(code_str)

        if len(posibilities) == 1:
            return getattr(Code, posibilities[0])
        else:
            return getattr(Code, rng.choice(posibilities))
    else:
        l = build_code_left_part(dst, size)
        r = build_code_right_part(ctx, src, size)

    return getattr(Code, f"{name}_{l}_{r}{postfix}")


class FukuAsmBody:
    def __init__(self):
        # Binary Arithmetic Instructions
        self._gen_iced_fns(BaseBuilder(name="add", inst=INST_PROPS["add"]))
        self._gen_iced_fns(BaseBuilder(name="adc", inst=INST_PROPS["adc"]))
        self._gen_iced_fns(BaseBuilder(name="sub", inst=INST_PROPS["sub"]))
        self._gen_iced_fns(BaseBuilder(name="sbb", inst=INST_PROPS["sbb"]))
        self._gen_iced_fns(BaseBuilder(name="imul", inst=INST_PROPS["imul"]))
        self._gen_iced_fns(BaseBuilder(name="mul", inst=INST_PROPS["mul"]))
        self._gen_iced_fns(BaseBuilder(name="idiv", inst=INST_PROPS["idiv"]))
        self._gen_iced_fns(BaseBuilder(name="div", inst=INST_PROPS["div"]))
        self._gen_iced_fns(
            BaseBuilder(
                name="inc", inst=INST_PROPS["inc"], exclude_inst=["INC_R16", "INC_R32"]
            )
        )
        self._gen_iced_fns(
            BaseBuilder(
                name="dec", inst=INST_PROPS["dec"], exclude_inst=["DEC_R16", "DEC_R32"]
            )
        )
        self._gen_iced_fns(BaseBuilder(name="neg", inst=INST_PROPS["neg"]))
        self._gen_iced_fns(BaseBuilder(name="cmp", inst=INST_PROPS["cmp"]))

        # Decimal Arithmetic Instructions
        self._gen_iced_fns(BaseBuilder(name="daa", inst=INST_PROPS["daa"]))
        self._gen_iced_fns(BaseBuilder(name="das", inst=INST_PROPS["das"]))
        self._gen_iced_fns(BaseBuilder(name="aaa", inst=INST_PROPS["aaa"]))
        self._gen_iced_fns(BaseBuilder(name="aas", inst=INST_PROPS["aas"]))

        # Logical Instructions
        self._gen_iced_fns(BaseBuilder(name="and", inst=INST_PROPS["and"]))
        self._gen_iced_fns(BaseBuilder(name="or", inst=INST_PROPS["or"]))
        self._gen_iced_fns(BaseBuilder(name="xor", inst=INST_PROPS["xor"]))
        self._gen_iced_fns(BaseBuilder(name="not", inst=INST_PROPS["not"]))

        # Data Transfer Instructions
        self._gen_iced_fns(BaseBuilder(name="mov", inst=INST_PROPS["mov"]))
        self._gen_iced_fns(BaseBuilder(name="xchg", inst=INST_PROPS["xchg"]))
        self._gen_iced_fns(
            BaseBuilder(name="bswap", inst=INST_PROPS["bswap"], exclude_postfix=["b"])
        )
        self._gen_iced_fns(BaseBuilder(name="xadd", inst=INST_PROPS["xadd"]))
        self._gen_iced_fns(BaseBuilder(name="cmpxchg", inst=INST_PROPS["cmpxchg"]))
        self._gen_iced_fns(
            BaseBuilder(name="push", inst=INST_PROPS["push"], exclude_postfix=["b"])
        )
        self._gen_iced_fns(
            BaseBuilder(name="pop", inst=INST_PROPS["pop"], exclude_postfix=["b"])
        )
        self._gen_iced_fns(BaseBuilder(name="cwd", inst=INST_PROPS["cwd"]))
        self._gen_iced_fns(BaseBuilder(name="cdq", inst=INST_PROPS["cdq"]))
        self._gen_iced_fns(BaseBuilder(name="cqo", inst=INST_PROPS["cqo"]))
        self._gen_iced_fns(BaseBuilder(name="cbw", inst=INST_PROPS["cbw"]))
        self._gen_iced_fns(BaseBuilder(name="cwde", inst=INST_PROPS["cwde"]))
        self._gen_iced_fns(BaseBuilder(name="cdqe", inst=INST_PROPS["cdqe"]))

        for inst_name in [
            "movzx",
            "movsx",
        ]:
            self._gen_iced_fns(
                BaseBuilder(
                    name=inst_name,
                    inst=INST_PROPS[inst_name],
                    postfix_modifier="byte_",
                    exclude_postfix=["b"],
                )
            )
            self._gen_iced_fns(
                BaseBuilder(
                    name=inst_name,
                    inst=INST_PROPS[inst_name],
                    postfix_modifier="word_",
                    exclude_postfix=["b", "w"],
                )
            )

        self._gen_iced_fns(
            BaseBuilder(
                name="movsxd",
                inst=INST_PROPS["movsxd"],
                postfix_modifier="word_",
                exclude_postfix=["b", "d", "q"],
            )
        )

        self._gen_iced_fns(
            BaseBuilder(
                name="movsxd",
                inst=INST_PROPS["movsxd"],
                postfix_modifier="dword_",
                exclude_postfix=["b", "w"],
            )
        )

        # Shift and Rotate Instructions
        self._gen_iced_fns(BaseBuilder(name="sar", inst=INST_PROPS["sar"]))
        self._gen_iced_fns(BaseBuilder(name="sar", inst=INST_PROPS["sar_cl"], cl=True))
        self._gen_iced_fns(BaseBuilder(name="shr", inst=INST_PROPS["shr"]))
        self._gen_iced_fns(BaseBuilder(name="shr", inst=INST_PROPS["shr_cl"], cl=True))
        self._gen_iced_fns(BaseBuilder(name="shl", inst=INST_PROPS["shl"]))
        self._gen_iced_fns(BaseBuilder(name="shl", inst=INST_PROPS["shl_cl"], cl=True))
        self._gen_iced_fns(
            BaseBuilder(name="shrd", inst=INST_PROPS["shrd"], exclude_postfix=["b"])
        )
        self._gen_iced_fns(
            BaseBuilder(
                name="shrd", inst=INST_PROPS["shrd_cl"], cl=True, exclude_postfix=["b"]
            )
        )
        self._gen_iced_fns(
            BaseBuilder(name="shld", inst=INST_PROPS["shld"], exclude_postfix=["b"])
        )
        self._gen_iced_fns(
            BaseBuilder(
                name="shld", inst=INST_PROPS["shld_cl"], cl=True, exclude_postfix=["b"]
            )
        )
        self._gen_iced_fns(BaseBuilder(name="ror", inst=INST_PROPS["ror"]))
        self._gen_iced_fns(BaseBuilder(name="ror", inst=INST_PROPS["ror_cl"], cl=True))
        self._gen_iced_fns(BaseBuilder(name="rol", inst=INST_PROPS["rol"]))
        self._gen_iced_fns(BaseBuilder(name="rol", inst=INST_PROPS["rol_cl"], cl=True))
        self._gen_iced_fns(BaseBuilder(name="rcr", inst=INST_PROPS["rcr"]))
        self._gen_iced_fns(BaseBuilder(name="rcr", inst=INST_PROPS["rcr_cl"], cl=True))
        self._gen_iced_fns(BaseBuilder(name="rcl", inst=INST_PROPS["rcl"]))
        self._gen_iced_fns(BaseBuilder(name="rcl", inst=INST_PROPS["rcl_cl"], cl=True))

        # Bit and Byte Instructions
        self._gen_iced_fns(
            BaseBuilder(
                name="bt", inst=INST_PROPS["bt"], exclude_postfix=["b"], max_imm_size=8
            )
        )
        self._gen_iced_fns(
            BaseBuilder(
                name="bts",
                inst=INST_PROPS["bts"],
                exclude_postfix=["b"],
                max_imm_size=8,
            )
        )
        self._gen_iced_fns(
            BaseBuilder(
                name="btr",
                inst=INST_PROPS["btr"],
                exclude_postfix=["b"],
                max_imm_size=8,
            )
        )
        self._gen_iced_fns(
            BaseBuilder(
                name="btc",
                inst=INST_PROPS["btc"],
                exclude_postfix=["b"],
                max_imm_size=8,
            )
        )
        self._gen_iced_fns(
            BaseBuilder(
                name="bsf",
                inst=INST_PROPS["bsf"],
                exclude_postfix=["b"],
                max_imm_size=8,
            )
        )
        self._gen_iced_fns(
            BaseBuilder(
                name="bsr",
                inst=INST_PROPS["bsr"],
                exclude_postfix=["b"],
                max_imm_size=8,
            )
        )

        # Control Transfer Instructions
        self._gen_iced_fns(BaseBuilder(name="int3", inst=INST_PROPS["int3"]))
        self._gen_iced_fns(BaseBuilder(name="leave", inst=INST_PROPS["leave"]))

        # String Instructions
        self._gen_func_body_string_inst_iced(
            "outs",
            x86_const.X86_EFLAGS_TEST_DF,
            mapping={
                8: "B_DX_M8",
                16: "W_DX_M16",
                32: "D_DX_M32",
            },
            exclude=["qw"],
        )
        self._gen_func_body_string_inst_iced(
            "movs",
            x86_const.X86_EFLAGS_TEST_DF,
            mapping={
                8: "B_M8_M8",
                16: "W_M16_M16",
                32: "D_M32_M32",
                64: "Q_M64_M64",
            },
        )
        self._gen_func_body_string_inst_iced(
            "cmps",
            x86_const.X86_EFLAGS_MODIFY_OF
            | x86_const.X86_EFLAGS_MODIFY_SF
            | x86_const.X86_EFLAGS_MODIFY_ZF
            | x86_const.X86_EFLAGS_MODIFY_AF
            | x86_const.X86_EFLAGS_MODIFY_PF
            | x86_const.X86_EFLAGS_MODIFY_CF,
            mapping={
                8: "B_M8_M8",
                16: "W_M16_M16",
                32: "D_M32_M32",
                64: "Q_M64_M64",
            },
        )
        self._gen_func_body_string_inst_iced(
            "stos",
            x86_const.X86_EFLAGS_TEST_DF,
            mapping={
                8: "B_M8_AL",
                16: "W_M16_AX",
                32: "D_M32_EAX",
                64: "Q_M64_RAX",
            },
        )
        self._gen_func_body_string_inst_iced(
            "lods",
            x86_const.X86_EFLAGS_TEST_DF,
            mapping={
                8: "B_AL_M8",
                16: "W_AX_M16",
                32: "D_EAX_M32",
                64: "Q_RAX_M64",
            },
        )
        self._gen_func_body_string_inst_iced(
            "scas",
            x86_const.X86_EFLAGS_MODIFY_OF
            | x86_const.X86_EFLAGS_MODIFY_SF
            | x86_const.X86_EFLAGS_MODIFY_ZF
            | x86_const.X86_EFLAGS_MODIFY_AF
            | x86_const.X86_EFLAGS_MODIFY_PF
            | x86_const.X86_EFLAGS_MODIFY_CF,
            mapping={
                8: "B_AL_M8",
                16: "W_AX_M16",
                32: "D_EAX_M32",
                64: "Q_RAX_M64",
            },
        )

        # Flag Control (EFLAG) Instructions
        self._gen_iced_fns(BaseBuilder(name="stc", inst=INST_PROPS["stc"]))
        self._gen_iced_fns(BaseBuilder(name="clc", inst=INST_PROPS["clc"]))
        self._gen_iced_fns(BaseBuilder(name="cmc", inst=INST_PROPS["cmc"]))
        self._gen_iced_fns(BaseBuilder(name="cld", inst=INST_PROPS["cld"]))
        self._gen_iced_fns(BaseBuilder(name="std", inst=INST_PROPS["std"]))
        self._gen_iced_fns(BaseBuilder(name="lahf", inst=INST_PROPS["lahf"]))
        self._gen_iced_fns(BaseBuilder(name="sahf", inst=INST_PROPS["sahf"]))
        self._gen_iced_fns(BaseBuilder(name="pusha", inst=INST_PROPS["pusha"]))
        self._gen_iced_fns(BaseBuilder(name="pushad", inst=INST_PROPS["pushad"]))
        self._gen_iced_fns(BaseBuilder(name="popa", inst=INST_PROPS["popa"]))
        self._gen_iced_fns(BaseBuilder(name="popad", inst=INST_PROPS["popad"]))
        self._gen_iced_fns(BaseBuilder(name="pushf", inst=INST_PROPS["pushf"]))
        self._gen_iced_fns(BaseBuilder(name="pushfd", inst=INST_PROPS["pushfd"]))
        self._gen_iced_fns(BaseBuilder(name="pushfq", inst=INST_PROPS["pushfq"]))
        self._gen_iced_fns(BaseBuilder(name="popf", inst=INST_PROPS["popf"]))
        self._gen_iced_fns(BaseBuilder(name="popfd", inst=INST_PROPS["popfd"]))
        self._gen_iced_fns(BaseBuilder(name="popfq", inst=INST_PROPS["popfq"]))
        self._gen_iced_fns(
            BaseBuilder(name="popcnt", inst=INST_PROPS["popcnt"], exclude_postfix=["b"])
        )
        self._gen_iced_fns(BaseBuilder(name="test", inst=INST_PROPS["test"]))

        # Miscellaneous Instructions
        self._gen_iced_fns(
            BaseBuilder(
                name="lea",
                inst=INST_PROPS["lea"],
                exclude_postfix=["b"],
                code_resolver=lambda _, _2, _3, _4, size: f"LEA_R{size}_M",
            )
        )
        self._gen_iced_fns(BaseBuilder(name="ud2", inst=INST_PROPS["ud2"]))
        self._gen_iced_fns(BaseBuilder(name="cpuid", inst=INST_PROPS["cpuid"]))

        # Random Number Generator Instructions
        self._gen_iced_fns(
            BaseBuilder(name="rdseed", inst=INST_PROPS["rdseed"], exclude_postfix=["b"])
        )
        self._gen_iced_fns(
            BaseBuilder(name="rdrand", inst=INST_PROPS["rdrand"], exclude_postfix=["b"])
        )

        # SYSTEM INSTRUCTIONS
        self._gen_iced_fns(BaseBuilder(name="hlt", inst=INST_PROPS["hlt"]))
        self._gen_iced_fns(BaseBuilder(name="rdtsc", inst=INST_PROPS["rdtsc"]))
        self._gen_iced_fns(BaseBuilder(name="lfence", inst=INST_PROPS["lfence"]))

    def _gen_fn(self, name: str, wrappers: list[PostfixedWrapper]):
        for wrapper in wrappers:
            class_name = f"{name}_{wrapper.postfix}" if wrapper.postfix else name
            setattr(self.__class__, class_name, wrapper.wrapper)

    def _gen_iced_fns(self, builder: BaseBuilder):
        name, wrappers = builder.build()
        self._gen_fn(name, wrappers)

    # Data Transfer Instructions
    def cmovcc_w(
        self,
        ctx: FukuAsmCtx,
        cond: FukuCondition,
        dst: FukuRegister,
        src: FukuOperand | FukuRegister,
    ):
        ctx.clear()

        if isinstance(src, FukuOperand):
            ctx.gen_pattern32_2em_op_r_word(0x0F, 0x40 | cond.value, src, dst)
        else:
            ctx.gen_pattern32_2em_rm_r_word(0x0F, 0x40 | cond.value, src, dst)

        ctx.gen_func_return(
            cond.to_capstone_cc(FukuToCapConvertType.CMOVCC), ADI_FL_JCC[cond.value]
        )

    def cmovcc_dw(
        self,
        ctx: FukuAsmCtx,
        cond: FukuCondition,
        dst: FukuRegister,
        src: FukuOperand | FukuRegister,
    ):
        ctx.clear()

        if isinstance(src, FukuOperand):
            ctx.gen_pattern32_2em_op_r(0x0F, 0x40 | cond.value, src, dst)
        else:
            ctx.gen_pattern32_2em_rm_r(0x0F, 0x40 | cond.value, src, dst)

        ctx.gen_func_return(
            cond.to_capstone_cc(FukuToCapConvertType.CMOVCC), ADI_FL_JCC[cond.value]
        )

    def cmovcc_qw(
        self,
        ctx: FukuAsmCtx,
        cond: FukuCondition,
        dst: FukuRegister,
        src: FukuOperand | FukuRegister,
    ):
        ctx.clear()

        if isinstance(src, FukuOperand):
            ctx.gen_pattern64_2em_op_r(0x0F, 0x40 | cond.value, src, dst)
        else:
            ctx.gen_pattern64_2em_rm_r(0x0F, 0x40 | cond.value, src, dst)

        ctx.gen_func_return(
            cond.to_capstone_cc(FukuToCapConvertType.CMOVCC), ADI_FL_JCC[cond.value]
        )

    def cmpxchg8b(self, ctx: FukuAsmCtx, dst: FukuOperand):
        ctx.clear()
        ctx.gen_pattern32_2em_op_idx(0x0F, 0xC7, dst, 1)
        ctx.gen_func_return(x86_const.X86_INS_CMPXCHG8B, x86_const.X86_EFLAGS_MODIFY_ZF)

    def cmpxchg16b(self, ctx: FukuAsmCtx, dst: FukuOperand):
        ctx.clear()
        ctx.gen_pattern64_2em_op_idx(0x0F, 0xC7, dst, 1)
        ctx.gen_func_return(
            x86_const.X86_INS_CMPXCHG16B, x86_const.X86_EFLAGS_MODIFY_ZF
        )

    # Binary Arithmetic Instructions
    def adcx_dw(
        self, ctx: FukuAsmCtx, dst: FukuRegister, src: FukuRegister | FukuOperand
    ):
        ctx.clear()

        if isinstance(src, FukuRegister):
            ctx.emit_b(FukuPrefix.FUKU_PREFIX_OVERRIDE_DATA.value)
            ctx.emit_optional_rex_32(dst, src)
            ctx.emit_b(0x0F)
            ctx.emit_b(0x38)
            ctx.emit_b(0xF6)
            ctx.emit_modrm(src, dst)
        else:
            ctx.emit_b(FukuPrefix.FUKU_PREFIX_OVERRIDE_DATA.value)
            ctx.emit_optional_rex_32(src, dst)
            ctx.emit_b(0x0F)
            ctx.emit_b(0x38)
            ctx.emit_b(0xF6)
            ctx.emit_operand(src, dst)

        ctx.gen_func_return(x86_const.X86_INS_ADCX, x86_const.X86_EFLAGS_MODIFY_CF)

    def adcx_qw(
        self, ctx: FukuAsmCtx, dst: FukuRegister, src: FukuRegister | FukuOperand
    ):
        ctx.clear()

        if isinstance(src, FukuRegister):
            ctx.emit_b(FukuPrefix.FUKU_PREFIX_OVERRIDE_DATA.value)
            ctx.emit_rex_64(dst, src)
            ctx.emit_b(0x0F)
            ctx.emit_b(0x38)
            ctx.emit_b(0xF6)
            ctx.emit_modrm(src, dst)
        else:
            ctx.emit_b(FukuPrefix.FUKU_PREFIX_OVERRIDE_DATA.value)
            ctx.emit_rex_64(src, dst)
            ctx.emit_b(0x0F)
            ctx.emit_b(0x38)
            ctx.emit_b(0xF6)
            ctx.emit_operand(src, dst)

        ctx.gen_func_return(x86_const.X86_INS_ADCX, x86_const.X86_EFLAGS_MODIFY_CF)

    def adox_dw(
        self, ctx: FukuAsmCtx, dst: FukuRegister, src: FukuRegister | FukuOperand
    ):
        ctx.clear()

        if isinstance(src, FukuRegister):
            ctx.emit_b(0xF3)
            ctx.emit_optional_rex_32(dst, src)
            ctx.emit_b(0x0F)
            ctx.emit_b(0x38)
            ctx.emit_b(0xF6)
            ctx.emit_modrm(src, dst)
        else:
            ctx.emit_b(0xF3)
            ctx.emit_optional_rex_32(src, dst)
            ctx.emit_b(0x0F)
            ctx.emit_b(0x38)
            ctx.emit_b(0xF6)
            ctx.emit_operand(src, dst)

        ctx.gen_func_return(x86_const.X86_INS_ADOX, x86_const.X86_EFLAGS_MODIFY_OF)

    def adox_qw(
        self, ctx: FukuAsmCtx, dst: FukuRegister, src: FukuRegister | FukuOperand
    ):
        ctx.clear()

        if isinstance(src, FukuRegister):
            ctx.emit_b(0xF3)
            ctx.emit_rex_64(dst, src)
            ctx.emit_b(0x0F)
            ctx.emit_b(0x38)
            ctx.emit_b(0xF6)
            ctx.emit_modrm(src, dst)
        else:
            ctx.emit_b(0xF3)
            ctx.emit_rex_64(src, dst)
            ctx.emit_b(0x0F)
            ctx.emit_b(0x38)
            ctx.emit_b(0xF6)
            ctx.emit_operand(src, dst)

        ctx.gen_func_return(x86_const.X86_INS_ADOX, x86_const.X86_EFLAGS_MODIFY_OF)

    # Decimal Arithmetic Instructions
    def aam(self, ctx: FukuAsmCtx, imm: FukuImmediate):
        ctx.clear()
        ctx.gen_pattern32_1em_immb(0xD4, FukuRegister(FukuRegisterEnum.REG_NONE), imm)
        ctx.gen_func_return(
            x86_const.X86_INS_AAM,
            x86_const.X86_EFLAGS_UNDEFINED_OF
            | x86_const.X86_EFLAGS_MODIFY_SF
            | x86_const.X86_EFLAGS_MODIFY_ZF
            | x86_const.X86_EFLAGS_UNDEFINED_AF
            | x86_const.X86_EFLAGS_MODIFY_PF
            | x86_const.X86_EFLAGS_UNDEFINED_CF,
        )

    def aad(self, ctx: FukuAsmCtx, imm: FukuImmediate):
        ctx.clear()
        ctx.gen_pattern32_1em_immb(0xD5, FukuRegister(FukuRegisterEnum.REG_NONE), imm)
        ctx.gen_func_return(
            x86_const.X86_INS_AAD,
            x86_const.X86_EFLAGS_UNDEFINED_OF
            | x86_const.X86_EFLAGS_MODIFY_SF
            | x86_const.X86_EFLAGS_MODIFY_ZF
            | x86_const.X86_EFLAGS_UNDEFINED_AF
            | x86_const.X86_EFLAGS_MODIFY_PF
            | x86_const.X86_EFLAGS_UNDEFINED_CF,
        )

    # Bit and Byte Instructions
    def setcc(
        self, ctx: FukuAsmCtx, cond: FukuCondition, dst: FukuRegister | FukuOperand
    ):
        ctx.clear()

        assert cond not in [FukuCondition.NO_CONDITION, FukuCondition.CONDITION_MAX]

        if isinstance(dst, FukuRegister):
            ctx.gen_pattern32_2em_rm_idx(0x0F, 0x90 | cond.value, dst, 0)
        else:
            ctx.gen_pattern32_2em_op_idx(0x0F, 0x90 | cond.value, dst, 0)

        ctx.gen_func_return(
            cond.to_capstone_cc(FukuToCapConvertType.SETCC), ADI_FL_JCC[cond.value]
        )

    # Control Transfer Instructions
    def jmp(self, ctx: FukuAsmCtx, src: FukuRegister | FukuOperand | FukuImmediate):
        ctx.clear()

        if isinstance(src, FukuRegister):
            ctx.gen_pattern32_1em_rm_idx(0xFF, src, 4)
        elif isinstance(src, FukuOperand):
            ctx.gen_pattern32_1em_op_idx(0xFF, src, 4)
        else:
            ctx.gen_pattern32_1em_immdw(
                0xE9, FukuRegister(FukuRegisterEnum.REG_NONE), src
            )

        ctx.gen_func_return(x86_const.X86_INS_JMP, 0)

    def jcc(self, ctx: FukuAsmCtx, cond: FukuCondition, imm: FukuImmediate):
        ctx.clear()

        assert cond not in [FukuCondition.NO_CONDITION, FukuCondition.CONDITION_MAX]

        ctx.gen_pattern32_2em_immdw(
            0x0F, 0x80 | cond.value, FukuRegister(FukuRegisterEnum.REG_NONE), imm
        )

        ctx.gen_func_return(
            cond.to_capstone_cc(FukuToCapConvertType.JCC), ADI_FL_JCC[cond.value]
        )

    def call(self, ctx: FukuAsmCtx, src: FukuRegister | FukuOperand | FukuImmediate):
        ctx.clear()

        if isinstance(src, FukuRegister):
            ctx.gen_pattern32_1em_rm_idx(0xFF, src, 2)
        elif isinstance(src, FukuOperand):
            ctx.gen_pattern32_1em_op_idx(0xFF, src, 2)
        else:
            ctx.gen_pattern32_1em_immdw(
                0xE8, FukuRegister(FukuRegisterEnum.REG_NONE), src
            )

        ctx.gen_func_return(x86_const.X86_INS_CALL, 0)

    def ret(self, ctx: FukuAsmCtx, imm: Optional[FukuImmediate] = None):
        ctx.clear()

        if imm is not None:
            ins = Instruction.create_u32(Code.RETNQ_IMM16, imm.to_iced())
        else:
            ins = Instruction.create(Code.RETNQ)
        gen_iced_ins(ctx, ins)

        ctx.gen_func_return(x86_const.X86_INS_RET, 0)

    def enter(self, ctx: FukuAsmCtx, size: FukuImmediate, nesting_level: int):
        ctx.clear()

        ins = Instruction.create_u32_u32(
            Code.ENTERQ_IMM16_IMM8, size.to_iced(), nesting_level
        )
        gen_iced_ins(ctx, ins)

        ctx.gen_func_return(x86_const.X86_INS_ENTER, 0)

    # SYSTEM INSTRUCTIONS
    def nop(self, ctx: FukuAsmCtx, n: int = 0):
        ctx.clear()

        if not n:
            n = rng.randint(1, 11)

        match n:
            case 2:
                ctx.emit_b(0x66)

            case 3:
                ctx.emit_b(0x0F)
                ctx.emit_b(0x1F)
                ctx.emit_b(0x00)

            case 4:
                ctx.emit_b(0x0F)
                ctx.emit_b(0x1F)
                ctx.emit_b(0x40)
                ctx.emit_b(0x00)

            case 5 | 6:
                if n == 6:
                    ctx.emit_b(0x66)

                ctx.emit_b(0x0F)
                ctx.emit_b(0x1F)
                ctx.emit_b(0x44)
                ctx.emit_b(0x00)
                ctx.emit_b(0x00)

            case 7:
                ctx.emit_b(0x0F)
                ctx.emit_b(0x1F)
                ctx.emit_b(0x80)
                ctx.emit_b(0x00)
                ctx.emit_b(0x00)
                ctx.emit_b(0x00)
                ctx.emit_b(0x00)

            case 8 | 9 | 10 | 11:
                if n >= 9:
                    if n >= 10:
                        if n == 11:
                            ctx.emit_b(0x66)
                        ctx.emit_b(0x66)
                    ctx.emit_b(0x66)

                ctx.emit_b(0x0F)
                ctx.emit_b(0x1F)
                ctx.emit_b(0x84)
                ctx.emit_b(0x00)
                ctx.emit_b(0x00)
                ctx.emit_b(0x00)
                ctx.emit_b(0x00)
                ctx.emit_b(0x00)

            case _:
                ctx.emit_b(0x90)

        ctx.gen_func_return(x86_const.X86_INS_NOP, 0)

    def _gen_func_body_string_inst_iced(
        self, name, cap_eflags, mapping: dict[int, str], exclude: list[str] = []
    ):
        def wrapper(size: int):
            def fn(self, ctx: FukuAsmCtx):
                ctx.clear()

                code = getattr(Code, f"{name.upper()}{mapping[size]}")
                ins = Instruction.create(code)
                gen_iced_ins(ctx, ins)

                ctx.gen_func_return(id, cap_eflags)

            return fn

        self._gen_fn(name, gen_default_postfix(wrapper, exclude=exclude))
