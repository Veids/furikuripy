from furikuripy.x86.fuku_operand import FukuPrefix


class FukuAsmCtxPattern:
    # emit 1 byte , emit modrm(regrm, idx)
    def gen_pattern32_1em_rm_idx(self, byte1, rm_reg, idx):
        self.emit_optional_rex_32(rm_reg)
        self.emit_b(byte1)
        self.emit_modrm(rm_reg, idx)

    def gen_pattern64_1em_rm_idx(self, byte1, rm_reg, idx):
        self.emit_rex_64(rm_reg)
        self.emit_b(byte1)
        self.emit_modrm(rm_reg, idx)

    # emit 2 bytes , emit modrm(regrm, idx)
    def gen_pattern32_2em_rm_idx(self, byte1, byte2, rm_reg, idx):
        self.emit_optional_rex_32(rm_reg)
        self.emit_b(byte1)
        self.emit_b(byte2)
        self.emit_modrm(rm_reg, idx)

    def gen_pattern64_2em_rm_idx(self, byte1, byte2, rm_reg, idx):
        self.emit_rex_64(rm_reg)
        self.emit_b(byte1)
        self.emit_b(byte2)
        self.emit_modrm(rm_reg, idx)

    # emit 1 byte , emit modrm(regrm, reg)
    def gen_pattern32_1em_rm_r(self, byte1, rm_reg, reg):
        self.emit_optional_rex_32(rm_reg, reg)
        self.emit_b(byte1)
        self.emit_modrm(rm_reg, reg)

    def gen_pattern64_1em_rm_r(self, byte1, rm_reg, reg):
        self.emit_rex_64(rm_reg, reg)
        self.emit_b(byte1)
        self.emit_modrm(rm_reg, reg)

    # emit 2 bytes , emit modrm(regrm, reg)
    def gen_pattern32_2em_rm_r(self, byte1, byte2, rm_reg, reg):
        self.emit_optional_rex_32(rm_reg, reg)
        self.emit_b(byte1)
        self.emit_b(byte2)
        self.emit_modrm(rm_reg, reg)

    def gen_pattern64_2em_rm_r(self, byte1, byte2, rm_reg, reg):
        self.emit_rex_64(rm_reg, reg)
        self.emit_b(byte1)
        self.emit_b(byte2)
        self.emit_modrm(rm_reg, reg)

    # emit 1 byte , emit imm b
    def gen_pattern32_1em_immb(self, byte1, rm_reg, imm):
        self.emit_optional_rex_32(rm_reg)
        self.emit_b(byte1)
        self.emit_immediate_b(imm)

    # emit 1 byte , emit imm w
    def gen_pattern32_1em_immw(self, byte1, rm_reg, imm):
        self.emit_optional_rex_32(rm_reg)
        self.emit_b(byte1)
        self.emit_immediate_w(imm)

    # emit 1 byte , emit imm dw
    def gen_pattern32_1em_immdw(self, byte1, rm_reg, imm):
        self.emit_optional_rex_32(rm_reg)
        self.emit_b(byte1)
        self.emit_immediate_dw(imm)

    def gen_pattern64_1em_immdw(self, byte1, rm_reg, imm):
        self.emit_rex_64(rm_reg)
        self.emit_b(byte1)
        self.emit_immediate_dw(imm)

    # emit 2 byte , emit imm dw
    def gen_pattern32_2em_immdw(self, byte1, byte2, rm_reg, imm):
        self.emit_optional_rex_32(rm_reg)
        self.emit_b(byte1)
        self.emit_b(byte2)
        self.emit_immediate_dw(imm)

    # emit 1 bytes , emit operand(regrm, idx)
    def gen_pattern32_1em_op_idx(self, byte1, operand, idx):
        self.emit_optional_rex_32(operand)
        self.emit_b(byte1)
        self.emit_operand(operand, idx)

    def gen_pattern64_1em_op_idx(self, byte1, operand, idx):
        self.emit_rex_64(operand)
        self.emit_b(byte1)
        self.emit_operand(operand, idx)

    # emit 2 bytes , emit operand(regrm, idx)
    def gen_pattern32_2em_op_idx(self, byte1, byte2, operand, idx):
        self.emit_optional_rex_32(operand)
        self.emit_b(byte1)
        self.emit_b(byte2)
        self.emit_operand(operand, idx)

    def gen_pattern64_2em_op_idx(self, byte1, byte2, operand, idx):
        self.emit_rex_64(operand)
        self.emit_b(byte1)
        self.emit_b(byte2)
        self.emit_operand(operand, idx)

    # emit 1 bytes , emit operand(regrm, reg)
    def gen_pattern32_1em_op_r(self, byte1, operand, reg):
        self.emit_optional_rex_32(operand, reg)
        self.emit_b(byte1)
        self.emit_operand(operand, reg)

    def gen_pattern64_1em_op_r(self, byte1, operand, reg):
        self.emit_rex_64(operand, reg)
        self.emit_b(byte1)
        self.emit_operand(operand, reg)

    # emit 2 bytes , emit operand(regrm, reg)
    def gen_pattern32_2em_op_r(self, byte1, byte2, operand, reg):
        self.emit_optional_rex_32(operand, reg)
        self.emit_b(byte1)
        self.emit_b(byte2)
        self.emit_operand(operand, reg)

    def gen_pattern64_2em_op_r(self, byte1, byte2, operand, reg):
        self.emit_rex_64(operand, reg)
        self.emit_b(byte1)
        self.emit_b(byte2)
        self.emit_operand(operand, reg)

    # emit 1 bytes , emit operand(regrm, idx) imm b
    def gen_pattern32_1em_op_idx_immb(self, byte1, operand, idx, imm):
        self.gen_pattern32_1em_op_idx(byte1, operand, idx)
        self.emit_immediate_b(imm)

    def gen_pattern64_1em_op_idx_immb(self, byte1, operand, idx, imm):
        self.gen_pattern64_1em_op_idx(byte1, operand, idx)
        self.emit_immediate_b(imm)

    # emit 1 bytes , emit operand(regrm, idx) imm w
    def gen_pattern32_1em_op_idx_immw(self, byte1, operand, idx, imm):
        self.gen_pattern32_1em_op_idx(byte1, operand, idx)
        self.emit_immediate_w(imm)

    # emit 1 bytes , emit operand(regrm, idx) imm dw
    def gen_pattern32_1em_op_idx_immdw(self, byte1, operand, idx, imm):
        self.gen_pattern32_1em_op_idx(byte1, operand, idx)
        self.emit_immediate_dw(imm)

    def gen_pattern64_1em_op_idx_immdw(self, byte1, operand, idx, imm):
        self.gen_pattern64_1em_op_idx(byte1, operand, idx)
        self.emit_immediate_dw(imm)

    # emit 2 bytes , emit operand(regrm, idx) imm b
    def gen_pattern32_2em_op_idx_immb(self, byte1, byte2, operand, idx, imm):
        self.gen_pattern32_2em_op_idx(byte1, byte2, operand, idx)
        self.emit_immediate_b(imm)

    def gen_pattern64_2em_op_idx_immb(self, byte1, byte2, operand, idx, imm):
        self.gen_pattern64_2em_op_idx(byte1, byte2, operand, idx)
        self.emit_immediate_b(imm)

    # emit 1 bytes , emit rm(regrm, idx) imm b
    def gen_pattern32_1em_rm_idx_immb(self, byte1, rm_reg, idx, imm):
        self.gen_pattern32_1em_rm_idx(byte1, rm_reg, idx)
        self.emit_immediate_b(imm)

    def gen_pattern64_1em_rm_idx_immb(self, byte1, rm_reg, idx, imm):
        self.gen_pattern64_1em_rm_idx(byte1, rm_reg, idx)
        self.emit_immediate_b(imm)

    # emit 1 bytes , emit rm(regrm, idx) imm w
    def gen_pattern32_1em_rm_idx_immw(self, byte1, rm_reg, idx, imm):
        self.gen_pattern32_1em_rm_idx(byte1, rm_reg, idx)
        self.emit_immediate_w(imm)

    # emit 1 bytes , emit rm(regrm, idx) imm dw
    def gen_pattern32_1em_rm_idx_immdw(self, byte1, rm_reg, idx, imm):
        self.gen_pattern32_1em_rm_idx(byte1, rm_reg, idx)
        self.emit_immediate_dw(imm)

    def gen_pattern64_1em_rm_idx_immdw(self, byte1, rm_reg, idx, imm):
        self.gen_pattern64_1em_rm_idx(byte1, rm_reg, idx)
        self.emit_immediate_dw(imm)

    # emit 2 bytes , emit rm(regrm, idx) imm b
    def gen_pattern32_2em_rm_idx_immb(self, byte1, byte2, rm_reg, idx, imm):
        self.gen_pattern32_2em_rm_idx(byte1, byte2, rm_reg, idx)
        self.emit_immediate_b(imm)

    def gen_pattern64_2em_rm_idx_immb(self, byte1, byte2, rm_reg, idx, imm):
        self.gen_pattern64_2em_rm_idx(byte1, byte2, rm_reg, idx)
        self.emit_immediate_b(imm)

    def gen_pattern32_1em_rm_r_word(self, byte1, rm_reg, reg):
        self.emit_b(FukuPrefix.FUKU_PREFIX_OVERRIDE_DATA.value)
        self.gen_pattern32_1em_rm_r(byte1, rm_reg, reg)

    def gen_pattern32_2em_rm_r_word(self, byte1, byte2, rm_reg, reg):
        self.emit_b(FukuPrefix.FUKU_PREFIX_OVERRIDE_DATA.value)
        self.gen_pattern32_2em_rm_r(byte1, byte2, rm_reg, reg)

    def gen_pattern32_1em_rm_idx_word(self, byte1, rm_reg, idx):
        self.emit_b(FukuPrefix.FUKU_PREFIX_OVERRIDE_DATA.value)
        self.gen_pattern32_1em_rm_idx(byte1, rm_reg, idx)

    def gen_pattern32_2em_rm_idx_word(self, byte1, byte2, rm_reg_idx, reg):
        self.emit_b(FukuPrefix.FUKU_PREFIX_OVERRIDE_DATA.value)
        self.gen_pattern32_2em_rm_idx(byte1, byte2, rm_reg_idx, reg)

    def gen_pattern32_1em_immw_word(self, byte1, rm_reg, imm):
        self.emit_b(FukuPrefix.FUKU_PREFIX_OVERRIDE_DATA.value)
        self.gen_pattern32_1em_immw(byte1, rm_reg, imm)

    def gen_pattern32_1em_op_r_word(self, byte1, rm_reg, reg):
        self.emit_b(FukuPrefix.FUKU_PREFIX_OVERRIDE_DATA.value)
        self.gen_pattern32_1em_op_r(byte1, rm_reg, reg)

    def gen_pattern32_2em_op_r_word(self, byte1, byte2, rm_reg_idx, reg):
        self.emit_b(FukuPrefix.FUKU_PREFIX_OVERRIDE_DATA.value)
        self.gen_pattern32_2em_op_r(byte1, byte2, rm_reg_idx, reg)

    def gen_pattern32_1em_op_idx_word(self, byte1, rm_reg, idx):
        self.emit_b(FukuPrefix.FUKU_PREFIX_OVERRIDE_DATA.value)
        self.gen_pattern32_1em_op_idx(byte1, rm_reg, idx)

    def gen_pattern32_2em_op_idx_word(self, byte1, byte2, rm_reg_idx, reg):
        self.emit_b(FukuPrefix.FUKU_PREFIX_OVERRIDE_DATA.value)
        self.gen_pattern32_2em_op_idx(byte1, byte2, rm_reg_idx, reg)

    def gen_pattern32_1em_op_idx_immb_word(self, byte1, operand, idx, imm):
        self.emit_b(FukuPrefix.FUKU_PREFIX_OVERRIDE_DATA.value)
        self.gen_pattern32_1em_op_idx_immb(byte1, operand, idx, imm)

    def gen_pattern32_2em_op_idx_immb_word(self, byte1, byte2, operand, idx, imm):
        self.emit_b(FukuPrefix.FUKU_PREFIX_OVERRIDE_DATA.value)
        self.gen_pattern32_2em_op_idx_immb(byte1, byte2, operand, idx, imm)

    def gen_pattern32_1em_rm_idx_immb_word(self, byte1, rm_reg, idx, imm):
        self.emit_b(FukuPrefix.FUKU_PREFIX_OVERRIDE_DATA.value)
        self.gen_pattern32_1em_rm_idx_immb(byte1, rm_reg, idx, imm)

    def gen_pattern32_2em_rm_idx_immb_word(self, byte1, byte2, rm_reg, idx, imm):
        self.emit_b(FukuPrefix.FUKU_PREFIX_OVERRIDE_DATA.value)
        self.gen_pattern32_2em_rm_idx_immb(byte1, byte2, rm_reg, idx, imm)

    def gen_pattern32_1em_rm_idx_immw_word(self, byte1, rm_reg, idx, imm):
        self.emit_b(FukuPrefix.FUKU_PREFIX_OVERRIDE_DATA.value)
        self.gen_pattern32_1em_rm_idx_immw(byte1, rm_reg, idx, imm)
