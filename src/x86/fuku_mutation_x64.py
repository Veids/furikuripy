from binascii import hexlify
from typing import Dict, Callable, List, Optional
from pydantic import BaseModel, ConfigDict
from capstone import x86_const, Cs, CS_ARCH_X86, CS_MODE_64

from common import rng, trace
from fuku_inst import FukuInst
from fuku_code_holder import FukuCodeHolder
from fuku_misc import FukuInstFlags, FukuObfuscationSettings, FUKU_ASSEMBLER_ARCH
from fuku_asm import FukuAsm, FukuAsmHoldType
from x86.fuku_mutation_ctx import FukuMutationCtx
from x86.mutation_templates.x64 import fukutate_64_jmp, fukutate_64_jcc, fukutate_64_ret, fukutate_64_mov, fukutate_64_xchg, fukutate_64_push, fukutate_64_pop, fuku_junk_64_generic


def gen_rules() -> Dict[int, Callable]:
    rules = {}

    rules[x86_const.X86_INS_JMP] = fukutate_64_jmp
    # rules[X86_INS_CALL] = fukutate_64_call;
    rules[x86_const.X86_INS_JO] = fukutate_64_jcc
    rules[x86_const.X86_INS_JNO] = fukutate_64_jcc
    rules[x86_const.X86_INS_JB] = fukutate_64_jcc
    rules[x86_const.X86_INS_JAE] = fukutate_64_jcc
    rules[x86_const.X86_INS_JE] = fukutate_64_jcc
    rules[x86_const.X86_INS_JNE] = fukutate_64_jcc
    rules[x86_const.X86_INS_JBE] = fukutate_64_jcc
    rules[x86_const.X86_INS_JA] = fukutate_64_jcc
    rules[x86_const.X86_INS_JS] = fukutate_64_jcc
    rules[x86_const.X86_INS_JNS] = fukutate_64_jcc
    rules[x86_const.X86_INS_JP] = fukutate_64_jcc
    rules[x86_const.X86_INS_JNP] = fukutate_64_jcc
    rules[x86_const.X86_INS_JL] = fukutate_64_jcc
    rules[x86_const.X86_INS_JGE] = fukutate_64_jcc
    rules[x86_const.X86_INS_JLE] = fukutate_64_jcc
    rules[x86_const.X86_INS_JG] = fukutate_64_jcc
    rules[x86_const.X86_INS_RET] = fukutate_64_ret

    rules[x86_const.X86_INS_MOV] = fukutate_64_mov
    rules[x86_const.X86_INS_XCHG] = fukutate_64_xchg
    # rules[x86_const.X86_INS_LEA] = fukutate_64_lea;
    rules[x86_const.X86_INS_PUSH] = fukutate_64_push
    rules[x86_const.X86_INS_POP] = fukutate_64_pop

    # ARITHMETIC
    # rules[x86_const.X86_INS_ADD] = fukutate_64_add;
    # rules[x86_const.X86_INS_OR] = fukutate_64_or;
    # rules[x86_const.X86_INS_ADC] = fukutate_64_adc;
    # rules[x86_const.X86_INS_SBB] = fukutate_64_sbb;
    # rules[x86_const.X86_INS_AND] = fukutate_64_and;
    # rules[x86_const.X86_INS_SUB] = fukutate_64_sub;
    # rules[x86_const.X86_INS_XOR] = fukutate_64_xor;
    # rules[x86_const.X86_INS_CMP] = fukutate_64_cmp;
    # rules[x86_const.X86_INS_INC] = fukutate_64_inc;
    # rules[x86_const.X86_INS_DEC] = fukutate_64_dec;
    # rules[x86_const.X86_INS_TEST] = fukutate_64_test;
    # rules[x86_const.X86_INS_NOT] = fukutate_64_not;
    # rules[x86_const.X86_INS_NEG] = fukutate_64_neg;
    # rules[x86_const.X86_INS_MUL] = fukutate_64_mul;
    # rules[x86_const.X86_INS_IMUL] = fukutate_64_imul;
    # rules[x86_const.X86_INS_DIV] = fukutate_64_div;
    # rules[x86_const.X86_INS_IDIV] = fukutate_64_idiv;

    # SHIFT
    # rules[x86_const.X86_INS_ROL] = fukutate_64_rol;
    # rules[x86_const.X86_INS_ROR] = fukutate_64_ror;
    # rules[x86_const.X86_INS_RCL] = fukutate_64_rcl;
    # rules[x86_const.X86_INS_RCR] = fukutate_64_rcr;
    # rules[x86_const.X86_INS_SAL] = fukutate_64_shl;//SAL is too SHL
    # rules[x86_const.X86_INS_SHL] = fukutate_64_shl;
    # rules[x86_const.X86_INS_SHR] = fukutate_64_shr;
    # rules[x86_const.X86_INS_SAR] = fukutate_64_sar;

    # //BITTEST
    # rules[x86_const.X86_INS_BT] = fukutate_64_bt;
    # rules[x86_const.X86_INS_BTS] = fukutate_64_bts;
    # rules[x86_const.X86_INS_BTR] = fukutate_64_btr;
    # rules[x86_const.X86_INS_BTC] = fukutate_64_btc;
    # rules[x86_const.X86_INS_BSF] = fukutate_64_bsf;
    # rules[x86_const.X86_INS_BSR] = fukutate_64_bsr;
    return rules


class FukuMutationX64(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    rules: Dict[int, Callable] = gen_rules()

    cs: Cs
    f_asm: FukuAsm = FukuAsm()
    settings: FukuObfuscationSettings

    def __init__(self, **kwargs):
        kwargs["cs"] = Cs(CS_ARCH_X86, CS_MODE_64)
        kwargs["cs"].detail = True

        super().__init__(**kwargs)

        self.f_asm.context.arch = FUKU_ASSEMBLER_ARCH.X64

    def obfuscate(self, code: FukuCodeHolder):
        ctx = FukuMutationCtx(
            f_asm = self.f_asm,
            code_holder = code,
            settings = self.settings
        )

        trace.info("Iterating...")
        self.obfuscate_lines(ctx, code.instructions[:], -1)

    def obfuscate_lines(self, ctx: FukuMutationCtx, instructions: List[FukuInst], recurse_idx: int):
        for inst in instructions:
            line_idx = instructions.index(inst)

            next_idx = line_idx + 1
            next_inst = None
            if next_idx != len(instructions):
                next_inst = instructions[next_idx]

            original_inst_idx = ctx.code_holder.instructions.index(inst)
            self.fukutuation(ctx, inst, next_inst)

            recurse_idx_up = 0
            if recurse_idx == -1:
                recurse_idx_up = rng.randint(0, self.settings.complexity + 1)
            else:
                recurse_idx_up = recurse_idx - 1

            if recurse_idx_up:
                if next_inst:
                    next_idx = ctx.code_holder.instructions.index(next_inst)
                else:
                    next_idx = len(ctx.code_holder.instructions)

                self.obfuscate_lines(ctx, instructions[original_inst_idx:next_idx], recurse_idx_up)


    def fukutuation(self, ctx: FukuMutationCtx, inst: FukuInst, next_inst: Optional[FukuInst]):
        if inst.flags & FukuInstFlags.FUKU_INST_JUNK_CODE:
            return

        is_chanced_junk = self.settings.roll_junk_chance()
        is_chanced_mutate = self.settings.roll_mutate_chance()

        if not (is_chanced_junk or is_chanced_mutate):
            return

        ctx.initialize_context(inst, next_inst)
        try:
            ctx.instruction = next(self.cs.disasm(inst.opcode, 0))
        except Exception as e:
            trace.error("Capstone failed to disassemble opcode: %s" % hexlify(inst.opcode))
            raise e

        self.f_asm.context.short_cfg = 0xFF & ~(self.settings.asm_cfg & rng.randint(0, 0xFF))

        was_junked = False
        was_mutated = False

        if is_chanced_junk:
            was_junked = self.fuku_junk(ctx)

            if was_junked:
                ctx.update_payload_inst_iter()

        if is_chanced_mutate:
            if fukutuate := self.rules.get(inst.id):
                self.f_asm.set_holder(
                    code_holder = ctx.code_holder,
                    hold_type = FukuAsmHoldType.ASSEMBLER_HOLD_TYPE_FIRST_OVERWRITE
                )
                self.f_asm.position = ctx.code_holder.instructions.index(inst)
                self.f_asm.first_emit = True

                was_mutated = fukutuate(ctx)

        if was_junked or was_mutated:
            if inst.id == -1:
                return

            # reset labels
            if ctx.original_start_label:
                ctx.original_start_label.inst.label = None
                ctx.calc_original_inst().label = ctx.original_start_label

            if ctx.payload_start_label:
                ctx.payload_inst.label = ctx.payload_start_label

            # reset source address and flags

            if (
                ctx.has_source_address or
                (not ctx.settings.is_not_allowed_unstable_stack and ctx.inst_flags & FukuInstFlags.FUKU_INST_BAD_STACK)
            ):
                idx = ctx.code_holder.instructions.index(ctx.calc_original_inst())
                end_idx = len(ctx.code_holder.instructions)
                if ctx.next_inst:
                    end_idx = ctx.code_holder.instructions.index(ctx.next_inst)

                for i, inst in enumerate(ctx.code_holder.instructions[idx:end_idx]):
                    if ctx.inst_flags & FukuInstFlags.FUKU_INST_BAD_STACK:
                        inst.flags |= FukuInstFlags.FUKU_INST_BAD_STACK

                    if ctx.has_source_address:
                        if i != 0:
                            inst.source_address = None
                        else:
                            inst.source_address = ctx.source_address

    def fuku_junk(self, ctx: FukuMutationCtx) -> bool:
        self.f_asm.set_holder(
            code_holder = ctx.code_holder,
            hold_type = FukuAsmHoldType.ASSEMBLER_HOLD_TYPE_NOOVERWRITE
        )
        self.f_asm.position = ctx.code_holder.instructions.index(ctx.payload_inst)
        self.f_asm.first_emit = False

        return fuku_junk_64_generic(ctx)
