#include <stdint.h>

int my_strncmp(const char *s1, const char *s2, int n);
void my_exit(int code);

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

typedef int8_t  s8;
typedef int16_t s16;
typedef int32_t s32;
typedef int64_t s64;

int fits_in_s8(s32 val) {
  return (INT8_MIN <= val) && (val <= INT8_MAX);
}

typedef enum StorageSize {
  S8  = 8,
  S16 = 16,
  S32 = 32,
  S64 = 64,
} StorageSize;

typedef enum EncodingExteions {
  ENCODING_EXTENSION_NONE = 0,
  ENCODING_EXTENSION_REGISTER,
  ENCODING_EXTENSION_OP_CODE,
  ENCODING_EXTENSION_PLUS_REGISTER,
} EncodingExteions;

typedef enum EncodingOperandType {
  ENCODING_OPERAND_TYPE_REGISTER = 1,
  ENCODING_OPERAND_TYPE_REGISTER_A,
  ENCODING_OPERAND_TYPE_REGISTER_OR_MEMORY,
  ENCODING_OPERAND_TYPE_XMM,
  ENCODING_OPERAND_TYPE_MEMORY,
  ENCODING_OPERAND_TYPE_IMMEDIATE,
} EncodingOperandType;

typedef struct EncodingOperand {
  EncodingOperandType type;
  StorageSize size;
} EncodingOperand;

typedef struct EncodingInstruction {
  u8 op_code[4];
  EncodingExteions extension;
  u8 op_code_extension;
  EncodingOperand operands[3];
  u8 operand_count;
} EncodingInstruction;

typedef enum DefaultOperationSize {
  DEFAULT_OPERATION_SIZE_32 = 1,
  DEFAULT_OPERATION_SIZE_64,
} DefaultOperationSize;

typedef struct Mnemonic {
  const char *name;
  DefaultOperationSize default_operation_size;
  const EncodingInstruction *encodings;
  u64 encoding_count;
} Mnemonic;

#define countof(...)\
  (sizeof((__VA_ARGS__)) / sizeof(*(__VA_ARGS__)))

#define EXT_NONE   .extension = ENCODING_EXTENSION_NONE,
#define EXT_R      .extension = ENCODING_EXTENSION_REGISTER,
#define EXT_PLUS_R .extension = ENCODING_EXTENSION_PLUS_REGISTER,
#define EXT_OPCODE(ext) \
  .extension = ENCODING_EXTENSION_OP_CODE, \
  .op_code_extension = ((ext) & 0b111),

#define R_8  { ENCODING_OPERAND_TYPE_REGISTER, 8  }
#define R_16 { ENCODING_OPERAND_TYPE_REGISTER, 16 }
#define R_32 { ENCODING_OPERAND_TYPE_REGISTER, 32 }
#define R_64 { ENCODING_OPERAND_TYPE_REGISTER, 64 }

#define R_AL  { ENCODING_OPERAND_TYPE_REGISTER_A, 8  }
#define R_AX  { ENCODING_OPERAND_TYPE_REGISTER_A, 16 }
#define R_EAX { ENCODING_OPERAND_TYPE_REGISTER_A, 32 }
#define R_RAX { ENCODING_OPERAND_TYPE_REGISTER_A, 64 }

#define M_8  { ENCODING_OPERAND_TYPE_MEMORY, 8  }
#define M_16 { ENCODING_OPERAND_TYPE_MEMORY, 16 }
#define M_32 { ENCODING_OPERAND_TYPE_MEMORY, 32 }
#define M_64 { ENCODING_OPERAND_TYPE_MEMORY, 64 }

#define RM_8  { ENCODING_OPERAND_TYPE_REGISTER_OR_MEMORY, 8  }
#define RM_16 { ENCODING_OPERAND_TYPE_REGISTER_OR_MEMORY, 16 }
#define RM_32 { ENCODING_OPERAND_TYPE_REGISTER_OR_MEMORY, 32 }
#define RM_64 { ENCODING_OPERAND_TYPE_REGISTER_OR_MEMORY, 64 }

#define IMM_8  { ENCODING_OPERAND_TYPE_IMMEDIATE, 8  }
#define IMM_16 { ENCODING_OPERAND_TYPE_IMMEDIATE, 16 }
#define IMM_32 { ENCODING_OPERAND_TYPE_IMMEDIATE, 32 }
#define IMM_64 { ENCODING_OPERAND_TYPE_IMMEDIATE, 64 }

#define XMM_32 { ENCODING_OPERAND_TYPE_XMM, 32 }
#define XMM_64 { ENCODING_OPERAND_TYPE_XMM, 64 }

#define ENCODING(opcode, extension_type, ...) { \
    .op_code = {\
        ((opcode) >> 24) & 0xFFu,\
        ((opcode) >> 16) & 0xFFu,\
        ((opcode) >> 8) & 0xFFu,\
         (opcode) & 0xFFu\
      },                                                              \
    extension_type                                         \
    .operands = { __VA_ARGS__ }, \
    .operand_count = countof((EncodingOperand[]){__VA_ARGS__}), \
  }

#define MNEMONIC(_name, size, ...) { \
    .name = #_name,\
    .default_operation_size = DEFAULT_OPERATION_SIZE_ ## size,\
    .encodings = (const EncodingInstruction[]){__VA_ARGS__},\
    .encoding_count = countof((EncodingInstruction[]){__VA_ARGS__}),\
  }

typedef enum InputMnemonic {
  MOV = 1,
} InputMnemonic;

typedef enum AssemblyOperandType {
  ASSEMBLY_OPERAND_TYPE_REGISTER = 1,
  ASSEMBLY_OPERAND_TYPE_HIGH_REGISTER,
  ASSEMBLY_OPERAND_TYPE_IMMEDIATE,
  ASSEMBLY_OPERAND_TYPE_MEMORY,
  ASSEMBLY_OPERAND_TYPE_XMM,
} AssemblyOperandType;

typedef enum AssemblyOperandRegisterType {
  ASSEMBLY_OPERAND_REGISTER_TYPE_A  = 0,
  ASSEMBLY_OPERAND_REGISTER_TYPE_C  = 1,
  ASSEMBLY_OPERAND_REGISTER_TYPE_D  = 2,
  ASSEMBLY_OPERAND_REGISTER_TYPE_B  = 3,
  ASSEMBLY_OPERAND_REGISTER_TYPE_SP = 4,
  ASSEMBLY_OPERAND_REGISTER_TYPE_BP = 5,
  ASSEMBLY_OPERAND_REGISTER_TYPE_SI = 6,
  ASSEMBLY_OPERAND_REGISTER_TYPE_DI = 7,
  ASSEMBLY_OPERAND_REGISTER_TYPE_8  = 8,
  ASSEMBLY_OPERAND_REGISTER_TYPE_9  = 9,
  ASSEMBLY_OPERAND_REGISTER_TYPE_10 = 10,
  ASSEMBLY_OPERAND_REGISTER_TYPE_11 = 11,
  ASSEMBLY_OPERAND_REGISTER_TYPE_12 = 12,
  ASSEMBLY_OPERAND_REGISTER_TYPE_13 = 13,
  ASSEMBLY_OPERAND_REGISTER_TYPE_14 = 14,
  ASSEMBLY_OPERAND_REGISTER_TYPE_15 = 15,
} AssemblyOperandRegisterType;

typedef enum AssemblyOperandHighRegisterType {
  ASSEMBLY_OPERAND_HIGH_REGISTER_TYPE_A = 4,
  ASSEMBLY_OPERAND_HIGH_REGISTER_TYPE_C = 5,
  ASSEMBLY_OPERAND_HIGH_REGISTER_TYPE_D = 6,
  ASSEMBLY_OPERAND_HIGH_REGISTER_TYPE_B = 7,
} AssemblyOperandHighRegisterType;

typedef enum MemoryIndexRegisterType {
  MEMORY_INDEX_REGISTER_TYPE_A  = 0,
  MEMORY_INDEX_REGISTER_TYPE_C  = 1,
  MEMORY_INDEX_REGISTER_TYPE_D  = 2,
  MEMORY_INDEX_REGISTER_TYPE_B  = 3,
  // RSP cannot be used as the index register
  MEMORY_INDEX_REGISTER_TYPE_BP = 5,
  MEMORY_INDEX_REGISTER_TYPE_SI = 6,
  MEMORY_INDEX_REGISTER_TYPE_DI = 7,
  MEMORY_INDEX_REGISTER_TYPE_8  = 8,
  MEMORY_INDEX_REGISTER_TYPE_9  = 9,
  MEMORY_INDEX_REGISTER_TYPE_10 = 10,
  MEMORY_INDEX_REGISTER_TYPE_11 = 11,
  MEMORY_INDEX_REGISTER_TYPE_12 = 12,
  MEMORY_INDEX_REGISTER_TYPE_13 = 13,
  MEMORY_INDEX_REGISTER_TYPE_14 = 14,
  MEMORY_INDEX_REGISTER_TYPE_15 = 15,
} MemoryIndexRegisterType;

typedef enum MemoryLocationType {
  MEMORY_LOCATION_TYPE_INSTRUCTION_POINTER_RELATIVE = 1,
  MEMORY_LOCATION_TYPE_INDIRECT,
  MEMORY_LOCATION_TYPE_STACK,
} MemoryLocationType;

typedef struct MemoryLocationInstructionPointerRelative {

} MemoryLocationInstructionPointerRelative;

typedef enum ScalingFactor {
  SCALING_FACTOR_1 = 0b00,
  SCALING_FACTOR_2 = 0b01,
  SCALING_FACTOR_4 = 0b10,
  SCALING_FACTOR_8 = 0b11,
} ScalingFactor;

typedef struct MemoryLocationIndirect {
  u8                       has_base;
  AssemblyOperandRegisterType base;
  u8                       has_index;
  MemoryIndexRegisterType  index;
  ScalingFactor            scale;
  s32                      disp;
} MemoryLocationIndirect;

typedef enum StackArea {
  STACK_AREA_LOCAL = 1,
  STACK_AREA_RECEIVED_ARGUMENT,
  STACK_AREA_CALL_TARGET_ARGUMENT,
} StackArea;

typedef struct MemoryLocationStack {
  StackArea area;
  s32 offset;
} MemoryLocationStack;

typedef struct AssemblyOperandRegister {
  AssemblyOperandRegisterType type;
  StorageSize              size;
} AssemblyOperandRegister;

typedef struct AssemblyOperandHighRegister {
  AssemblyOperandHighRegisterType type;
} AssemblyOperandHighRegister;

typedef struct AssemblyOperandImmediate {
  u64         value;
  StorageSize size;
} AssemblyOperandImmediate;

typedef struct AssemblyOperandXmm {
  AssemblyOperandRegisterType type;
  StorageSize              size;
} AssemblyOperandXmm;

typedef struct AssemblyOperandMemory {
  MemoryLocationType type;
  union {
    MemoryLocationInstructionPointerRelative instruction_pointer_relative;
    MemoryLocationIndirect                   indirect;
    MemoryLocationStack                      stack;
  };
} AssemblyOperandMemory;

typedef struct AssemblyOperand {
  AssemblyOperandType type;
  union {
    AssemblyOperandRegister     reg;
    AssemblyOperandHighRegister high_reg;
    AssemblyOperandImmediate    imm;
    AssemblyOperandXmm          xmm;
    AssemblyOperandMemory       memory;
  };
} AssemblyOperand;

typedef struct AssemblyInstruction {
  InputMnemonic mnemonic;
  const AssemblyOperand operands[3];
  u8 operand_count;
} AssemblyInstruction;

typedef enum REXByte {
  REX   = 0b01000000,
  REX_W = 0b01001000, // 0 = Storage size determined by CS.D; 1 = 64 Bit Storage Size
  REX_R = 0b01000100, // Extension of the ModR/M reg field
  REX_X = 0b01000010, // Extension of the SIB index field
  REX_B = 0b01000001, // Extension of the ModR/M r/m field, SIB base field, or Opcode reg field
} REXByte;

typedef enum Mod {
  MOD_Displacement_0   = 0b00,
  MOD_Displacement_s8  = 0b01,
  MOD_Displacement_s32 = 0b10,
  MOD_Register         = 0b11,
} Mod;

const Mnemonic mov = MNEMONIC(mov, 32,
  ENCODING(0x88, EXT_R,         RM_8,  R_8),
  ENCODING(0x89, EXT_R,         RM_16, R_16),
  ENCODING(0x89, EXT_R,         RM_32, R_32),
  ENCODING(0x89, EXT_R,         RM_64, R_64),
  ENCODING(0x8A, EXT_R,         R_8,   RM_8),
  ENCODING(0x8B, EXT_R,         R_16,  RM_16),
  ENCODING(0x8B, EXT_R,         R_32,  RM_32),
  ENCODING(0x8B, EXT_R,         R_64,  RM_64),
  ENCODING(0xC6, EXT_OPCODE(0), RM_8,  IMM_8),
  ENCODING(0xC7, EXT_OPCODE(0), RM_16, IMM_16),
  ENCODING(0xC7, EXT_OPCODE(0), RM_32, IMM_32),
  ENCODING(0xC7, EXT_OPCODE(0), RM_64, IMM_32),
  ENCODING(0xB8, EXT_PLUS_R,    R_16,  IMM_16),
  ENCODING(0xB8, EXT_PLUS_R,    R_32,  IMM_32),
  ENCODING(0xB8, EXT_PLUS_R,    R_64,  IMM_64),
);

int operand_compare(const AssemblyOperand *a, const EncodingOperand *b) {
  switch (b->type) {
    case ENCODING_OPERAND_TYPE_REGISTER:
      return ((a->type == ASSEMBLY_OPERAND_TYPE_REGISTER) &&
              (a->reg.size == b->size)) ||
             ((a->type == ASSEMBLY_OPERAND_TYPE_HIGH_REGISTER) &&
              (b->size == S8));
    case ENCODING_OPERAND_TYPE_REGISTER_A:
      return ((a->type == ASSEMBLY_OPERAND_TYPE_REGISTER) &&
              (a->reg.type == ASSEMBLY_OPERAND_REGISTER_TYPE_A) &&
              (a->reg.size == b->size));
    case ENCODING_OPERAND_TYPE_REGISTER_OR_MEMORY:
      return ((a->type == ASSEMBLY_OPERAND_TYPE_REGISTER) &&
              (a->reg.size == b->size)) ||
             ((a->type == ASSEMBLY_OPERAND_TYPE_HIGH_REGISTER) &&
              (b->size == S8)) ||
             (a->type == ASSEMBLY_OPERAND_TYPE_MEMORY);
    case ENCODING_OPERAND_TYPE_IMMEDIATE:
      return (a->type == ASSEMBLY_OPERAND_TYPE_IMMEDIATE) &&
             (a->imm.size == b->size);
    case ENCODING_OPERAND_TYPE_MEMORY:
      return (a->type == ASSEMBLY_OPERAND_TYPE_MEMORY);
    case ENCODING_OPERAND_TYPE_XMM:
      return (a->type == ASSEMBLY_OPERAND_TYPE_XMM) &&
             (a->xmm.size == b->size);
  }
}

void print_bytes(const char *bytes, u8 length) {
  asm volatile(
      "syscall"
    : /* no outputs */
    : "a"(1), "S"(bytes), "d"(length), "D"(1)
    : "memory", "rcx", "r11"
  );
}

#define print(msg) print_bytes((msg), sizeof(msg))

void print_byte(u8 byte) {
  print_bytes((char*)&byte, 1);
}

int is_extended_register(u8 type) {
  return type & 0b1000;
}

int is_uniform_byte_register(const AssemblyOperandRegister *reg) {
  return reg->size == S8 &&
         (reg->type == ASSEMBLY_OPERAND_REGISTER_TYPE_SP ||
          reg->type == ASSEMBLY_OPERAND_REGISTER_TYPE_BP ||
          reg->type == ASSEMBLY_OPERAND_REGISTER_TYPE_SI ||
          reg->type == ASSEMBLY_OPERAND_REGISTER_TYPE_DI);
}

typedef enum EncodingPrefix {
  ENCODING_PREFIX_OPERAND_SIZE_OVERRIDE = 0x66,
  ENCODING_PREFIX_ADDRESS_SIZE_OVERRIDE = 0x67,
} EncodingPrefix;

typedef struct ModRM {
  Mod mod;
  u8  reg : 3;
  u8  r_m : 3;
} ModRM;

typedef struct SIB {
  u8 scale : 2;
  u8 index : 3;
  u8 base  : 3;
} SIB;

typedef struct EncodingResult {
  EncodingPrefix prefix : 8;
  u8             rex;
  u8             op_code[4];
  s8             mod_rm_needed;
  ModRM          mod_rm;
  SIB            sib;
  u8             disp_bytes;
  s32            disp;
  u8             imm_bytes;
  u64            imm;
} EncodingResult;

void
print_encoding(const EncodingResult *encoding) {
  if (encoding->prefix != 0) {
    print_byte(encoding->prefix);
  }
  if (encoding->rex) {
    print_byte(encoding->rex);
  }
  for (int i = 0; i < countof(encoding->op_code); i++) {
    if (encoding->op_code[i] != 0) {
      print_byte(encoding->op_code[i]);
    }
  }
  if (encoding->mod_rm_needed) {
    print_byte(
      ((encoding->mod_rm.mod & 0b011) << 6) |
      ((encoding->mod_rm.reg & 0b111) << 3) |
      ((encoding->mod_rm.r_m & 0b111) << 0)
    );

    // SIB
    if ((encoding->mod_rm.r_m == 0b100) &&
        (encoding->mod_rm.mod != 0b11)) {
      print_byte(
        ((encoding->sib.scale & 0b011) << 6) |
        ((encoding->sib.index & 0b111) << 3) |
        ((encoding->sib.base  & 0b111) << 0)
      );
    }
  }
  if (encoding->disp_bytes > 0) {
    print_bytes((char*)&encoding->disp, encoding->disp_bytes);
  }
  if (encoding->imm_bytes > 0) {
    print_bytes((char*)&encoding->imm, encoding->imm_bytes);
  }
}

#define ICE(msg) print_bytes("ICE: " msg, sizeof("ICE: " msg))

void
generate_sib_byte(
    u8 has_base,
    u8 base,
    u8 index,
    u8 scale,
    s32 disp,
    EncodingResult *result) {
  result->mod_rm.r_m = 0b100;
  result->sib.scale = scale & 0b11;
  result->sib.index = index & 0b111;

  if (disp == 0) {
    result->mod_rm.mod = 0b00;
  } else if (fits_in_s8(disp)) {
    result->mod_rm.mod = 0b01;
    result->disp_bytes = 1;
    result->disp = disp;
  } else {
    result->mod_rm.mod = 0b10;
    result->disp_bytes = 4;
    result->disp = disp;
  }

  if (has_base) {
    result->sib.base = base & 0b111;
    if (((base & 0b111) == 0b101) &&
        (disp == 0)) {
      /* If the displacement is 0, mod=00 by default. In this mode, base=101
       * enables displacement-only mode. So if the base normally ends in 101,
       * a different SIB needs to be used with disp8=0 and therefore mod=01
       */
      result->mod_rm.mod = 0b01;
      result->disp_bytes = 1;
      result->disp = 0;
    }
  } else {
    /* If the address has no base, then displacement-only mode can be enabled
     * with base=101, mod=00.
     */
    result->sib.base = 0b101;
    result->mod_rm.mod = 0b00;
    result->disp_bytes = 4;
    result->disp = disp;
  }
}

EncodingResult
encode(
    const AssemblyInstruction *assembly,
    const EncodingInstruction *encoding) {
  if (assembly->operand_count != encoding->operand_count) {
    ICE("incompatible operand count in instruction encoding\n");
    return (EncodingResult){0};
  }

  EncodingResult result = {0};
  int cannot_use_rex = 0;

  result.op_code[0] = encoding->op_code[0];
  result.op_code[1] = encoding->op_code[1];
  result.op_code[2] = encoding->op_code[2];
  result.op_code[3] = encoding->op_code[3];

  if (encoding->extension == ENCODING_EXTENSION_OP_CODE) {
    /* A digit between 0 and 7 indicates that the ModR/M byte of the instruction
     * uses only the r/m (register or memory) operand. The reg field contains
     * the digit that provides an extension to the instruction's opcode.
     */
    result.mod_rm_needed = 1;
    result.mod_rm.reg = encoding->op_code_extension & 0b111;
  }

  for (int operand_index = 0; operand_index < assembly->operand_count; operand_index++) {
    const AssemblyOperand *assembly_operand = &assembly->operands[operand_index];
    const EncodingOperand *encoding_operand = &encoding->operands[operand_index];

    if (encoding_operand->size == S16) {
      result.prefix = ENCODING_PREFIX_OPERAND_SIZE_OVERRIDE;
    }

    if ((encoding->extension == ENCODING_EXTENSION_PLUS_REGISTER) &&
        (encoding_operand->type == ENCODING_OPERAND_TYPE_REGISTER)) {
      /* Volume 2 - 3.1.1.1 Opcode Column in the Instruction Summary Table (Instructions without VEX Prefix)
       * Indicated the lower 3 bits of the opcode byte is used to encode the register operand
       * without a modR/M byte. The instruction lists the corresponding hexadecimal value of the opcode byte with low
       * 3 bits as 000b. In non-64-bit mode, a register code, from 0 through 7, is added to the hexadecimal value of the
       * opcode byte. In 64-bit mode, indicates the four bit field of REX.b and opcode[2:0] field encodes the register
       * operand of the instruction. “+ro” is applicable only in 64-bit mode. See Table 3-1 for the codes.
       */
      result.op_code[3] += assembly_operand->reg.type & 0b111;
    }

    switch(assembly_operand->type) {
      case ASSEMBLY_OPERAND_TYPE_REGISTER: {
        const AssemblyOperandRegister *reg = &assembly_operand->reg;
        if (reg->size == S64) {
          // TODO: Verify this
          // Any 64-bit operand forces the REX.w bit to be set
          result.rex |= REX_W;
        }
        if (is_uniform_byte_register(reg)) {
          /* For legacy registers, accessing word-size and above is unaffected
             * by the REX byte. When accessing byte registers, AL, CL, DL, and BL
             * are unaffected by the REX byte. Otherwise, if the REX byte is
             * absent, the high-byte registers (AH, CH, DH, and BH) are used, and
             * if the REX byte is present, the unform-byte registers (DIL, SIL,
             * BPL, and SPL) are used.
           */
          result.rex |= REX;
        }
        if (is_extended_register(reg->type)) {
          /* Any extended register (R8-R15) requires the REX byte to be set.
           * REX.B signals that the ModR/m r/m field uses an extended register.
           * REX.R signals that the ModR/M reg field uses an extended register.
           */
          if (encoding_operand->type == ENCODING_OPERAND_TYPE_REGISTER_OR_MEMORY) {
            result.rex |= REX_B;
          } else {
            result.rex |= REX_R;
          }
        }

        if (encoding->extension == ENCODING_EXTENSION_REGISTER) {
          // Indicates that the ModR/M byte of the instruction contains a register operand and an r/m operand.
          if (encoding_operand->type == ENCODING_OPERAND_TYPE_REGISTER) {
            result.mod_rm_needed = 1;
            result.mod_rm.reg = reg->type & 0b111;
          } else if (encoding_operand->type == ENCODING_OPERAND_TYPE_REGISTER_OR_MEMORY) {
            result.mod_rm_needed = 1;
            result.mod_rm.r_m = reg->type & 0b111;
            result.mod_rm.mod = MOD_Register;
          }
        } else if (encoding->extension == ENCODING_EXTENSION_OP_CODE) {
          /* A digit between 0 and 7 indicates that the ModR/M byte of the
             * instruction uses only the r/m (register or memory) operand. The
             * reg field contains the digit that provides an extension to the
             * instruction's opcode.
           */
          result.mod_rm_needed = 1;
          result.mod_rm.r_m = reg->type & 0b111;
          result.mod_rm.mod = MOD_Register;
        }
        break;
      }
      case ASSEMBLY_OPERAND_TYPE_HIGH_REGISTER: {
        const AssemblyOperandHighRegister *reg = &assembly_operand->high_reg;
        /* High-byte registers (AH, CH, DH, and BH) are distinguished from their
         * uniform-byte counterparts (DIL, SIL, BPL, and SPL) by the absence of
         * a REX byte. It is an error to have a high-byte register in an
         * instruction that needs a REX byte.
         */
        cannot_use_rex = 1;

        if (encoding->extension == ENCODING_EXTENSION_REGISTER) {
          // Indicates that the ModR/M byte of the instruction contains a register operand and an r/m operand.
          if (encoding_operand->type == ENCODING_OPERAND_TYPE_REGISTER) {
            result.mod_rm_needed = 1;
            result.mod_rm.reg = reg->type & 0b111;
          } else if (encoding_operand->type == ENCODING_OPERAND_TYPE_REGISTER_OR_MEMORY) {
            result.mod_rm_needed = 1;
            result.mod_rm.r_m = reg->type & 0b111;
            result.mod_rm.mod = MOD_Register;
          }
        } else if (encoding->extension == ENCODING_EXTENSION_OP_CODE) {
          /* A digit between 0 and 7 indicates that the ModR/M byte of the
           * instruction uses only the r/m (register or memory) operand. The
           * reg field contains the digit that provides an extension to the
           * instruction's opcode.
           */
          result.mod_rm_needed = 1;
          result.mod_rm.r_m = reg->type & 0b111;
          result.mod_rm.mod = MOD_Register;
        }
        break;
      }
      case ASSEMBLY_OPERAND_TYPE_MEMORY: {
        const AssemblyOperandMemory *mem = &assembly_operand->memory;
        switch(mem->type) {
          case MEMORY_LOCATION_TYPE_INDIRECT: {
            const MemoryLocationIndirect *indirect = &mem->indirect;
            if (indirect->has_index) {
              generate_sib_byte(indirect->has_base, indirect->base,
                                indirect->index, indirect->scale,
                                indirect->disp, &result);
            } else if (indirect->has_base) {
              if ((indirect->base & 0b111) == 0b100) {
                /* Base=100 (RSP, R12) can't be encoded in R/M without SIB, so
                 * use the invalid index 0b100 and scale 1.
                 */
                generate_sib_byte(1, indirect->base, 0b100, SCALING_FACTOR_1,
                                  indirect->disp, &result);
              } else {
                result.mod_rm.r_m = indirect->base & 0b111;
                if (indirect->disp == 0) {
                  if ((indirect->base & 0b111) == 0b101) {
                    result.mod_rm.mod = 0b01;
                    result.disp_bytes = 1;
                    result.disp = 0;
                  } else {
                    result.mod_rm.mod = 0b00;
                  }
                } else if (fits_in_s8(indirect->disp)) {
                  result.mod_rm.mod = 0b01;
                  result.disp_bytes = 1;
                  result.disp = indirect->disp;
                } else {
                  result.mod_rm.mod = 0b10;
                  result.disp_bytes = 4;
                  result.disp = indirect->disp;
                }
              }
            } else {
              // Displacement-only mode. In 64-bit mode, this requires a SIB
              // byte with index=0b100.
              // If this were encoded without a SIB byte in just the MOD and R/M
              // bits, it would enable RIP-relative addressing
              // TODO: Add RIP-relative addressing support
              generate_sib_byte(0, 0, 0b100, SCALING_FACTOR_1, indirect->disp,
                                &result);
            }
            if (indirect->has_base &&
                is_extended_register(indirect->base)) {
              // REX.B signals that the indirect memory base is extended.
              result.rex |= REX_B;
            }
            if (indirect->has_index &&
                is_extended_register(indirect->index)) {
              // REX.X signals that the indirect memory index is extended.
              result.rex |= REX_X;
            }
            break;
          }
          case MEMORY_LOCATION_TYPE_INSTRUCTION_POINTER_RELATIVE: {
            // FIXME: implement this
            break;
          }
          case MEMORY_LOCATION_TYPE_STACK: {
            // FIXME: implement this
            break;
          }
        }
        break;
      }
      case ASSEMBLY_OPERAND_TYPE_IMMEDIATE: {
        const AssemblyOperandImmediate *imm = &assembly_operand->imm;
        result.imm_bytes = imm->size / 8;
        result.imm = imm->value;
        break;
      }
      case ASSEMBLY_OPERAND_TYPE_XMM: {
        const AssemblyOperandXmm *xmm = &assembly_operand->xmm;
        // FIXME: implement this
        break;
      }
    }
  }

  if ((result.rex != 0) && cannot_use_rex) {
    print("error: cannot use high-byte register in an instruction requiring a REX byte\n");
    return (EncodingResult){0};
  }

  return result;
}


#define INSTRUCTION(_mnemonic, ...) (const AssemblyInstruction){ \
    .mnemonic=(_mnemonic),              \
    .operands={__VA_ARGS__},            \
    .operand_count=countof((AssemblyOperand[]){__VA_ARGS__}),\
  }

#define RAX {.type=ASSEMBLY_OPERAND_TYPE_REGISTER, .reg={.type=ASSEMBLY_OPERAND_REGISTER_TYPE_A,  .size=S64}}
#define RCX {.type=ASSEMBLY_OPERAND_TYPE_REGISTER, .reg={.type=ASSEMBLY_OPERAND_REGISTER_TYPE_C,  .size=S64}}
#define RDX {.type=ASSEMBLY_OPERAND_TYPE_REGISTER, .reg={.type=ASSEMBLY_OPERAND_REGISTER_TYPE_D,  .size=S64}}
#define RBX {.type=ASSEMBLY_OPERAND_TYPE_REGISTER, .reg={.type=ASSEMBLY_OPERAND_REGISTER_TYPE_B,  .size=S64}}
#define RSP {.type=ASSEMBLY_OPERAND_TYPE_REGISTER, .reg={.type=ASSEMBLY_OPERAND_REGISTER_TYPE_SP, .size=S64}}
#define RBP {.type=ASSEMBLY_OPERAND_TYPE_REGISTER, .reg={.type=ASSEMBLY_OPERAND_REGISTER_TYPE_BP, .size=S64}}
#define RSI {.type=ASSEMBLY_OPERAND_TYPE_REGISTER, .reg={.type=ASSEMBLY_OPERAND_REGISTER_TYPE_SI, .size=S64}}
#define RDI {.type=ASSEMBLY_OPERAND_TYPE_REGISTER, .reg={.type=ASSEMBLY_OPERAND_REGISTER_TYPE_DI, .size=S64}}
#define R8  {.type=ASSEMBLY_OPERAND_TYPE_REGISTER, .reg={.type=ASSEMBLY_OPERAND_REGISTER_TYPE_8,  .size=S64}}
#define R9  {.type=ASSEMBLY_OPERAND_TYPE_REGISTER, .reg={.type=ASSEMBLY_OPERAND_REGISTER_TYPE_9,  .size=S64}}
#define R10 {.type=ASSEMBLY_OPERAND_TYPE_REGISTER, .reg={.type=ASSEMBLY_OPERAND_REGISTER_TYPE_10, .size=S64}}
#define R11 {.type=ASSEMBLY_OPERAND_TYPE_REGISTER, .reg={.type=ASSEMBLY_OPERAND_REGISTER_TYPE_11, .size=S64}}
#define R12 {.type=ASSEMBLY_OPERAND_TYPE_REGISTER, .reg={.type=ASSEMBLY_OPERAND_REGISTER_TYPE_12, .size=S64}}
#define R13 {.type=ASSEMBLY_OPERAND_TYPE_REGISTER, .reg={.type=ASSEMBLY_OPERAND_REGISTER_TYPE_13, .size=S64}}
#define R14 {.type=ASSEMBLY_OPERAND_TYPE_REGISTER, .reg={.type=ASSEMBLY_OPERAND_REGISTER_TYPE_14, .size=S64}}
#define R15 {.type=ASSEMBLY_OPERAND_TYPE_REGISTER, .reg={.type=ASSEMBLY_OPERAND_REGISTER_TYPE_15, .size=S64}}

#define EAX  {.type=ASSEMBLY_OPERAND_TYPE_REGISTER, .reg={.type=ASSEMBLY_OPERAND_REGISTER_TYPE_A,  .size=S32}}
#define ECX  {.type=ASSEMBLY_OPERAND_TYPE_REGISTER, .reg={.type=ASSEMBLY_OPERAND_REGISTER_TYPE_C,  .size=S32}}
#define EDX  {.type=ASSEMBLY_OPERAND_TYPE_REGISTER, .reg={.type=ASSEMBLY_OPERAND_REGISTER_TYPE_D,  .size=S32}}
#define EBX  {.type=ASSEMBLY_OPERAND_TYPE_REGISTER, .reg={.type=ASSEMBLY_OPERAND_REGISTER_TYPE_B,  .size=S32}}
#define ESP  {.type=ASSEMBLY_OPERAND_TYPE_REGISTER, .reg={.type=ASSEMBLY_OPERAND_REGISTER_TYPE_SP, .size=S32}}
#define EBP  {.type=ASSEMBLY_OPERAND_TYPE_REGISTER, .reg={.type=ASSEMBLY_OPERAND_REGISTER_TYPE_BP, .size=S32}}
#define ESI  {.type=ASSEMBLY_OPERAND_TYPE_REGISTER, .reg={.type=ASSEMBLY_OPERAND_REGISTER_TYPE_SI, .size=S32}}
#define EDI  {.type=ASSEMBLY_OPERAND_TYPE_REGISTER, .reg={.type=ASSEMBLY_OPERAND_REGISTER_TYPE_DI, .size=S32}}
#define R8D  {.type=ASSEMBLY_OPERAND_TYPE_REGISTER, .reg={.type=ASSEMBLY_OPERAND_REGISTER_TYPE_8,  .size=S32}}
#define R9D  {.type=ASSEMBLY_OPERAND_TYPE_REGISTER, .reg={.type=ASSEMBLY_OPERAND_REGISTER_TYPE_9,  .size=S32}}
#define R10D {.type=ASSEMBLY_OPERAND_TYPE_REGISTER, .reg={.type=ASSEMBLY_OPERAND_REGISTER_TYPE_10, .size=S32}}
#define R11D {.type=ASSEMBLY_OPERAND_TYPE_REGISTER, .reg={.type=ASSEMBLY_OPERAND_REGISTER_TYPE_11, .size=S32}}
#define R12D {.type=ASSEMBLY_OPERAND_TYPE_REGISTER, .reg={.type=ASSEMBLY_OPERAND_REGISTER_TYPE_12, .size=S32}}
#define R13D {.type=ASSEMBLY_OPERAND_TYPE_REGISTER, .reg={.type=ASSEMBLY_OPERAND_REGISTER_TYPE_13, .size=S32}}
#define R14D {.type=ASSEMBLY_OPERAND_TYPE_REGISTER, .reg={.type=ASSEMBLY_OPERAND_REGISTER_TYPE_14, .size=S32}}
#define R15D {.type=ASSEMBLY_OPERAND_TYPE_REGISTER, .reg={.type=ASSEMBLY_OPERAND_REGISTER_TYPE_15, .size=S32}}

#define AX   {.type=ASSEMBLY_OPERAND_TYPE_REGISTER, .reg={.type=ASSEMBLY_OPERAND_REGISTER_TYPE_A,  .size=S16}}
#define CX   {.type=ASSEMBLY_OPERAND_TYPE_REGISTER, .reg={.type=ASSEMBLY_OPERAND_REGISTER_TYPE_C,  .size=S16}}
#define DX   {.type=ASSEMBLY_OPERAND_TYPE_REGISTER, .reg={.type=ASSEMBLY_OPERAND_REGISTER_TYPE_D,  .size=S16}}
#define BX   {.type=ASSEMBLY_OPERAND_TYPE_REGISTER, .reg={.type=ASSEMBLY_OPERAND_REGISTER_TYPE_B,  .size=S16}}
#define _SP  {.type=ASSEMBLY_OPERAND_TYPE_REGISTER, .reg={.type=ASSEMBLY_OPERAND_REGISTER_TYPE_SP, .size=S16}}
#define _BP  {.type=ASSEMBLY_OPERAND_TYPE_REGISTER, .reg={.type=ASSEMBLY_OPERAND_REGISTER_TYPE_BP, .size=S16}}
#define _SI  {.type=ASSEMBLY_OPERAND_TYPE_REGISTER, .reg={.type=ASSEMBLY_OPERAND_REGISTER_TYPE_SI, .size=S16}}
#define _DI  {.type=ASSEMBLY_OPERAND_TYPE_REGISTER, .reg={.type=ASSEMBLY_OPERAND_REGISTER_TYPE_DI, .size=S16}}
#define R8W  {.type=ASSEMBLY_OPERAND_TYPE_REGISTER, .reg={.type=ASSEMBLY_OPERAND_REGISTER_TYPE_8,  .size=S16}}
#define R9W  {.type=ASSEMBLY_OPERAND_TYPE_REGISTER, .reg={.type=ASSEMBLY_OPERAND_REGISTER_TYPE_9,  .size=S16}}
#define R10W {.type=ASSEMBLY_OPERAND_TYPE_REGISTER, .reg={.type=ASSEMBLY_OPERAND_REGISTER_TYPE_10, .size=S16}}
#define R11W {.type=ASSEMBLY_OPERAND_TYPE_REGISTER, .reg={.type=ASSEMBLY_OPERAND_REGISTER_TYPE_11, .size=S16}}
#define R12W {.type=ASSEMBLY_OPERAND_TYPE_REGISTER, .reg={.type=ASSEMBLY_OPERAND_REGISTER_TYPE_12, .size=S16}}
#define R13W {.type=ASSEMBLY_OPERAND_TYPE_REGISTER, .reg={.type=ASSEMBLY_OPERAND_REGISTER_TYPE_13, .size=S16}}
#define R14W {.type=ASSEMBLY_OPERAND_TYPE_REGISTER, .reg={.type=ASSEMBLY_OPERAND_REGISTER_TYPE_14, .size=S16}}
#define R15W {.type=ASSEMBLY_OPERAND_TYPE_REGISTER, .reg={.type=ASSEMBLY_OPERAND_REGISTER_TYPE_15, .size=S16}}

#define AL   {.type=ASSEMBLY_OPERAND_TYPE_REGISTER, .reg={.type=ASSEMBLY_OPERAND_REGISTER_TYPE_A,  .size=S8}}
#define CL   {.type=ASSEMBLY_OPERAND_TYPE_REGISTER, .reg={.type=ASSEMBLY_OPERAND_REGISTER_TYPE_C,  .size=S8}}
#define DL   {.type=ASSEMBLY_OPERAND_TYPE_REGISTER, .reg={.type=ASSEMBLY_OPERAND_REGISTER_TYPE_D,  .size=S8}}
#define BL   {.type=ASSEMBLY_OPERAND_TYPE_REGISTER, .reg={.type=ASSEMBLY_OPERAND_REGISTER_TYPE_B,  .size=S8}}
#define SPL  {.type=ASSEMBLY_OPERAND_TYPE_REGISTER, .reg={.type=ASSEMBLY_OPERAND_REGISTER_TYPE_SP, .size=S8}}
#define BPL  {.type=ASSEMBLY_OPERAND_TYPE_REGISTER, .reg={.type=ASSEMBLY_OPERAND_REGISTER_TYPE_BP, .size=S8}}
#define SIL  {.type=ASSEMBLY_OPERAND_TYPE_REGISTER, .reg={.type=ASSEMBLY_OPERAND_REGISTER_TYPE_SI, .size=S8}}
#define DIL  {.type=ASSEMBLY_OPERAND_TYPE_REGISTER, .reg={.type=ASSEMBLY_OPERAND_REGISTER_TYPE_DI, .size=S8}}
#define R8B  {.type=ASSEMBLY_OPERAND_TYPE_REGISTER, .reg={.type=ASSEMBLY_OPERAND_REGISTER_TYPE_8,  .size=S8}}
#define R9B  {.type=ASSEMBLY_OPERAND_TYPE_REGISTER, .reg={.type=ASSEMBLY_OPERAND_REGISTER_TYPE_9,  .size=S8}}
#define R10B {.type=ASSEMBLY_OPERAND_TYPE_REGISTER, .reg={.type=ASSEMBLY_OPERAND_REGISTER_TYPE_10, .size=S8}}
#define R11B {.type=ASSEMBLY_OPERAND_TYPE_REGISTER, .reg={.type=ASSEMBLY_OPERAND_REGISTER_TYPE_11, .size=S8}}
#define R12B {.type=ASSEMBLY_OPERAND_TYPE_REGISTER, .reg={.type=ASSEMBLY_OPERAND_REGISTER_TYPE_12, .size=S8}}
#define R13B {.type=ASSEMBLY_OPERAND_TYPE_REGISTER, .reg={.type=ASSEMBLY_OPERAND_REGISTER_TYPE_13, .size=S8}}
#define R14B {.type=ASSEMBLY_OPERAND_TYPE_REGISTER, .reg={.type=ASSEMBLY_OPERAND_REGISTER_TYPE_14, .size=S8}}
#define R15B {.type=ASSEMBLY_OPERAND_TYPE_REGISTER, .reg={.type=ASSEMBLY_OPERAND_REGISTER_TYPE_15, .size=S8}}

#define AH   {.type=ASSEMBLY_OPERAND_TYPE_HIGH_REGISTER, .high_reg={.type=ASSEMBLY_OPERAND_HIGH_REGISTER_TYPE_A}}
#define CH   {.type=ASSEMBLY_OPERAND_TYPE_HIGH_REGISTER, .high_reg={.type=ASSEMBLY_OPERAND_HIGH_REGISTER_TYPE_C}}
#define DH   {.type=ASSEMBLY_OPERAND_TYPE_HIGH_REGISTER, .high_reg={.type=ASSEMBLY_OPERAND_HIGH_REGISTER_TYPE_D}}
#define BH   {.type=ASSEMBLY_OPERAND_TYPE_HIGH_REGISTER, .high_reg={.type=ASSEMBLY_OPERAND_HIGH_REGISTER_TYPE_B}}

#define IMM8(v)  {ASSEMBLY_OPERAND_TYPE_IMMEDIATE, .imm={.value=(v), .size=S8}}
#define IMM16(v) {ASSEMBLY_OPERAND_TYPE_IMMEDIATE, .imm={.value=(v), .size=S16}}
#define IMM32(v) {ASSEMBLY_OPERAND_TYPE_IMMEDIATE, .imm={.value=(v), .size=S32}}
#define IMM64(v) {ASSEMBLY_OPERAND_TYPE_IMMEDIATE, .imm={.value=(v), .size=S64}}

#define MEM_BASE_INDEX_SCALE_DISP(_base, _index, _scale, _disp) {              \
    .type=ASSEMBLY_OPERAND_TYPE_MEMORY,                                        \
    .memory={                                                                  \
      .type=MEMORY_LOCATION_TYPE_INDIRECT,                                     \
      .indirect = {                                                            \
          .has_base = 1,                                                       \
          .base = ASSEMBLY_OPERAND_REGISTER_TYPE_ ## _base,                    \
          .has_index = 1,                                                      \
          .index = MEMORY_INDEX_REGISTER_TYPE_ ## _index,                      \
          .scale = SCALING_FACTOR_ ## _scale,                                  \
          .disp = _disp,                                                       \
    }}}
#define MEM_BASE_INDEX_DISP(_base, _index, _disp) {                            \
    .type=ASSEMBLY_OPERAND_TYPE_MEMORY,                                        \
    .memory={                                                                  \
      .type=MEMORY_LOCATION_TYPE_INDIRECT,                                     \
      .indirect = {                                                            \
          .has_base = 1,                                                       \
          .base = ASSEMBLY_OPERAND_REGISTER_TYPE_ ## _base,                    \
          .has_index = 1,                                                      \
          .index = MEMORY_INDEX_REGISTER_TYPE_ ## _index,                      \
          .scale = SCALING_FACTOR_ ## 1,                                       \
          .disp = _disp,                                                       \
    }}}
#define MEM_BASE_INDEX_SCALE(_base, _index, _scale) {                          \
    .type=ASSEMBLY_OPERAND_TYPE_MEMORY,                                        \
    .memory={                                                                  \
      .type=MEMORY_LOCATION_TYPE_INDIRECT,                                     \
      .indirect = {                                                            \
          .has_base = 1,                                                       \
          .base = ASSEMBLY_OPERAND_REGISTER_TYPE_ ## _base,                    \
          .has_index = 1,                                                      \
          .index = MEMORY_INDEX_REGISTER_TYPE_ ## _index,                      \
          .scale = SCALING_FACTOR_ ## _scale,                                  \
          .disp = 0,                                                           \
    }}}
#define MEM_BASE_INDEX(_base, _index) {                                        \
    .type=ASSEMBLY_OPERAND_TYPE_MEMORY,                                        \
    .memory={                                                                  \
      .type=MEMORY_LOCATION_TYPE_INDIRECT,                                     \
      .indirect = {                                                            \
          .has_base = 1,                                                       \
          .base = ASSEMBLY_OPERAND_REGISTER_TYPE_ ## _base,                    \
          .has_index = 1,                                                      \
          .index = MEMORY_INDEX_REGISTER_TYPE_ ## _index,                      \
          .scale = SCALING_FACTOR_ ## 1,                                       \
          .disp = 0,                                                           \
    }}}
#define MEM_INDEX_SCALE_DISP(_index, _scale, _disp) {                          \
    .type=ASSEMBLY_OPERAND_TYPE_MEMORY,                                        \
    .memory={                                                                  \
      .type=MEMORY_LOCATION_TYPE_INDIRECT,                                     \
      .indirect = {                                                            \
          .has_base = 0,                                                       \
          .has_index = 1,                                                      \
          .index = MEMORY_INDEX_REGISTER_TYPE_ ## _index,                      \
          .scale = SCALING_FACTOR_ ## _scale,                                  \
          .disp = _disp,                                                       \
    }}}
#define MEM_INDEX_DISP(_index, _disp) {                                        \
    .type=ASSEMBLY_OPERAND_TYPE_MEMORY,                                        \
    .memory={                                                                  \
      .type=MEMORY_LOCATION_TYPE_INDIRECT,                                     \
      .indirect = {                                                            \
          .has_base = 0,                                                       \
          .has_index = 1,                                                      \
          .index = MEMORY_INDEX_REGISTER_TYPE_ ## _index,                      \
          .scale = SCALING_FACTOR_ ## 1,                                       \
          .disp = _disp,                                                       \
    }}}
#define MEM_INDEX_SCALE(_index, _scale) {                                      \
    .type=ASSEMBLY_OPERAND_TYPE_MEMORY,                                        \
    .memory={                                                                  \
      .type=MEMORY_LOCATION_TYPE_INDIRECT,                                     \
      .indirect = {                                                            \
          .has_base = 0,                                                       \
          .has_index = 1,                                                      \
          .index = MEMORY_INDEX_REGISTER_TYPE_ ## _index,                      \
          .scale = SCALING_FACTOR_ ## _scale,                                  \
          .disp = 0,                                                           \
    }}}
#define MEM_INDEX(_index) {                                                    \
    .type=ASSEMBLY_OPERAND_TYPE_MEMORY,                                        \
    .memory={                                                                  \
      .type=MEMORY_LOCATION_TYPE_INDIRECT,                                     \
      .indirect = {                                                            \
          .has_base = 0,                                                       \
          .has_index = 1,                                                      \
          .index = MEMORY_INDEX_REGISTER_TYPE_ ## _index,                      \
          .scale = SCALING_FACTOR_ ## 1,                                       \
          .disp = 0,                                                           \
    }}}
#define MEM_BASE_DISP(_base, _disp) {                                          \
    .type=ASSEMBLY_OPERAND_TYPE_MEMORY,                                        \
    .memory={                                                                  \
      .type=MEMORY_LOCATION_TYPE_INDIRECT,                                     \
      .indirect = {                                                            \
          .has_base = 1,                                                       \
          .base = ASSEMBLY_OPERAND_REGISTER_TYPE_ ## _base,                    \
          .has_index = 0,                                                      \
          .disp = _disp,                                                       \
    }}}
#define MEM_BASE(_base) {                                                      \
    .type=ASSEMBLY_OPERAND_TYPE_MEMORY,                                        \
    .memory={                                                                  \
      .type=MEMORY_LOCATION_TYPE_INDIRECT,                                     \
      .indirect = {                                                            \
          .has_base = 1,                                                       \
          .base = ASSEMBLY_OPERAND_REGISTER_TYPE_ ## _base,                    \
          .has_index = 0,                                                      \
          .disp = 0,                                                           \
    }}}
#define MEM_DISP(_disp) {                                                      \
    .type=ASSEMBLY_OPERAND_TYPE_MEMORY,                                        \
    .memory={                                                                  \
      .type=MEMORY_LOCATION_TYPE_INDIRECT,                                     \
      .indirect = {                                                            \
          .has_base = 0,                                                       \
          .has_index = 0,                                                      \
          .disp = _disp,                                                       \
    }}}
#define MEM_INDEX_DISP(_index, _disp) {                                        \
    .type=ASSEMBLY_OPERAND_TYPE_MEMORY,                                        \
    .memory={                                                                  \
      .type=MEMORY_LOCATION_TYPE_INDIRECT,                                     \
      .indirect = {                                                            \
          .has_base = 0,                                                       \
          .has_index = 1,                                                      \
          .index = MEMORY_INDEX_REGISTER_TYPE_ ## _index,                      \
          .scale = SCALING_FACTOR_ ## 1,                                       \
          .disp = _disp,                                                       \
    }}}
#define MEM() {                                                                \
    .type=ASSEMBLY_OPERAND_TYPE_MEMORY,                                        \
    .memory={                                                                  \
      .type=MEMORY_LOCATION_TYPE_INDIRECT,                                     \
      .indirect = {                                                            \
          .has_base = 0,                                                       \
          .has_index = 0,                                                      \
          .disp = 0,                                                           \
    }}}

__attribute__((force_align_arg_pointer))
void
_start() {
  const AssemblyInstruction *ins =
      &INSTRUCTION(
          MOV,
          RCX,
          MEM_BASE_INDEX_SCALE_DISP(
              11,
              SI,
              2,
              0x1234
          )
      );

  const Mnemonic *mnemonic = &mov;
  const EncodingInstruction *encodings[32];
  int matched_encodings = 0;
  for (int i = 0; i < mnemonic->encoding_count; i++) {
    const EncodingInstruction *encoding = &mnemonic->encodings[i];
    if (encoding->operand_count != ins->operand_count) continue;
    int match = 1;
    for (int j = 0; j < ins->operand_count; j++) {
      if (!operand_compare(&ins->operands[j], &encoding->operands[j])) {
        match = 0;
        break;
      }

    }
    if (!match)
      continue;
    encodings[matched_encodings++] = encoding;
  }
  if (matched_encodings == 0) {
    print("error: no instruction encodings found for provided assembly\n");
    return;
  }

  for (int i = 0; i < matched_encodings; i++) {
    EncodingResult result = encode(ins, encodings[i]);
    print_encoding(&result);
  }

  my_exit(0);
}

int my_strncmp(const char *s1, const char *s2, int n) {
  while (n && (*s1 == *s2)) {
    s1++;
    s2++;
    n--;
  }
  if (n == 0) return 0;
  return *s1 - *s2;
}

void my_exit(int code) {
  asm volatile (
      "syscall"
      :
      : "a"(0x3c), "D"(code)
  );
  __builtin_unreachable();
}
