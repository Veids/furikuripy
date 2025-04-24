class FukuAsmCtxPattern:
    # emit 1 byte , emit modrm(regrm, idx)
    def gen_pattern32_1em_rm_idx(self, byte1, rm_reg, idx):
        self.emit_optional_rex_32(rm_reg)
        self.emit_b(byte1)
        self.emit_modrm(rm_reg, idx)

    # emit 1 byte , emit imm dw
    def gen_pattern32_1em_immdw(self, byte1, rm_reg, imm):
        self.emit_optional_rex_32(rm_reg)
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
