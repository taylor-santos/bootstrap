#include <stdint.h>

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

typedef int8_t  s8;
typedef int16_t s16;
typedef int32_t s32;
typedef int64_t s64;

typedef enum StorageSize {
  S8  = 8,
  S16 = 16,
  S32 = 32,
  S64 = 64,
} StorageSize;

typedef enum InstructionExtensionType {
  INSTRUCTION_EXTENSION_TYPE_NONE = 0,
  INSTRUCTION_EXTENSION_TYPE_REGISTER,
  INSTRUCTION_EXTENSION_TYPE_OP_CODE,
  INSTRUCTION_EXTENSION_TYPE_PLUS_REGISTER,
} InstructionExtensionType;

typedef enum OperandEncodingType {
  OPERAND_ENCODING_TYPE_REGISTER = 1,
  OPERAND_ENCODING_TYPE_REGISTER_A,
  OPERAND_ENCODING_TYPE_REGISTER_OR_MEMORY,
  OPERAND_ENCODING_TYPE_XMM,
  OPERAND_ENCODING_TYPE_MEMORY,
  OPERAND_ENCODING_TYPE_IMMEDIATE,
} OperandEncodingType;

typedef struct OperandEncoding {
  OperandEncodingType type;
  StorageSize size;
} OperandEncoding;

typedef struct InstructionEncoding {
  u8 op_code[4];
  InstructionExtensionType extension;
  u8 op_code_extension;
  OperandEncoding operands[3];
  u8 operand_count;
} InstructionEncoding;

typedef enum DefaultOperationSize {
  DEFAULT_OPERATION_SIZE_32 = 1,
  DEFAULT_OPERATION_SIZE_64,
} DefaultOperationSize;

typedef struct Mnemonic {
  const char *name;
  DefaultOperationSize default_operation_size;
  const InstructionEncoding *encodings;
  u64 encoding_count;
} Mnemonic;

#define countof(...)\
  (sizeof((__VA_ARGS__)) / sizeof(*(__VA_ARGS__)))

#define EXT_NONE   .extension = INSTRUCTION_EXTENSION_TYPE_NONE,
#define EXT_R      .extension = INSTRUCTION_EXTENSION_TYPE_REGISTER,
#define EXT_PLUS_R .extension = INSTRUCTION_EXTENSION_TYPE_PLUS_REGISTER,
#define EXT_OPCODE(ext) \
  .extension = INSTRUCTION_EXTENSION_TYPE_OP_CODE, \
  .op_code_extension = ((ext) & 0b111),

#define R_8  { OPERAND_ENCODING_TYPE_REGISTER, 8  }
#define R_16 { OPERAND_ENCODING_TYPE_REGISTER, 16 }
#define R_32 { OPERAND_ENCODING_TYPE_REGISTER, 32 }
#define R_64 { OPERAND_ENCODING_TYPE_REGISTER, 64 }

#define R_AL  { OPERAND_ENCODING_TYPE_REGISTER_A, 8  }
#define R_AX  { OPERAND_ENCODING_TYPE_REGISTER_A, 16 }
#define R_EAX { OPERAND_ENCODING_TYPE_REGISTER_A, 32 }
#define R_RAX { OPERAND_ENCODING_TYPE_REGISTER_A, 64 }

#define M_8  { OPERAND_ENCODING_TYPE_MEMORY, 8  }
#define M_16 { OPERAND_ENCODING_TYPE_MEMORY, 16 }
#define M_32 { OPERAND_ENCODING_TYPE_MEMORY, 32 }
#define M_64 { OPERAND_ENCODING_TYPE_MEMORY, 64 }

#define RM_8  { OPERAND_ENCODING_TYPE_REGISTER_OR_MEMORY, 8  }
#define RM_16 { OPERAND_ENCODING_TYPE_REGISTER_OR_MEMORY, 16 }
#define RM_32 { OPERAND_ENCODING_TYPE_REGISTER_OR_MEMORY, 32 }
#define RM_64 { OPERAND_ENCODING_TYPE_REGISTER_OR_MEMORY, 64 }

#define IMM_8  { OPERAND_ENCODING_TYPE_IMMEDIATE, 8  }
#define IMM_16 { OPERAND_ENCODING_TYPE_IMMEDIATE, 16 }
#define IMM_32 { OPERAND_ENCODING_TYPE_IMMEDIATE, 32 }
#define IMM_64 { OPERAND_ENCODING_TYPE_IMMEDIATE, 64 }

#define XMM_32 { OPERAND_ENCODING_TYPE_XMM, 32 }
#define XMM_64 { OPERAND_ENCODING_TYPE_XMM, 64 }

#define ENCODING(opcode, extension_type, ...) { \
    .op_code = {\
        ((opcode) >> 24) & 0xFFu,\
        ((opcode) >> 16) & 0xFFu,\
        ((opcode) >> 8) & 0xFFu,\
         (opcode) & 0xFFu\
      },                                                              \
    extension_type                                         \
    .operands = { __VA_ARGS__ }, \
    .operand_count = countof((OperandEncoding[]){__VA_ARGS__}), \
  }

#define MNEMONIC(_name, size, ...) { \
    .name = #_name,\
    .default_operation_size = DEFAULT_OPERATION_SIZE_ ## size,\
    .encodings = (const InstructionEncoding[]){__VA_ARGS__},\
    .encoding_count = countof((InstructionEncoding[]){__VA_ARGS__}),\
  }

typedef enum InputMnemonic {
  MOV = 1,
} InputMnemonic;

typedef enum InputOperandType {
  INPUT_OPERAND_TYPE_REGISTER = 1,
  INPUT_OPERAND_TYPE_IMMEDIATE,
  INPUT_OPERAND_TYPE_XMM,
  INPUT_OPERAND_TYPE_MEMORY,
} InputOperandType;

typedef enum InputOperandRegisterType {
  INPUT_OPERAND_REGISTER_TYPE_A  = 0,
  INPUT_OPERAND_REGISTER_TYPE_C  = 1,
  INPUT_OPERAND_REGISTER_TYPE_D  = 2,
  INPUT_OPERAND_REGISTER_TYPE_B  = 3,
  INPUT_OPERAND_REGISTER_TYPE_SP = 4,
  INPUT_OPERAND_REGISTER_TYPE_BP = 5,
  INPUT_OPERAND_REGISTER_TYPE_SI = 6,
  INPUT_OPERAND_REGISTER_TYPE_DI = 7,
  INPUT_OPERAND_REGISTER_TYPE_8  = 8,
  INPUT_OPERAND_REGISTER_TYPE_9  = 9,
  INPUT_OPERAND_REGISTER_TYPE_10 = 10,
  INPUT_OPERAND_REGISTER_TYPE_11 = 11,
  INPUT_OPERAND_REGISTER_TYPE_12 = 12,
  INPUT_OPERAND_REGISTER_TYPE_13 = 13,
  INPUT_OPERAND_REGISTER_TYPE_14 = 14,
  INPUT_OPERAND_REGISTER_TYPE_15 = 15,
} InputOperandRegisterType;

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
  InputOperandRegisterType base_register;
  u8                       has_index;
  InputOperandRegisterType index;
  ScalingFactor            scale;
  s32                      offset;
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

typedef struct InputOperandRegister {
  InputOperandRegisterType type;
  StorageSize              size;
} InputOperandRegister;

typedef struct InputOperandImmediate {
  u64         value;
  StorageSize size;
} InputOperandImmediate;

typedef struct InputOperandXmm {
  InputOperandRegisterType type;
  StorageSize              size;
} InputOperandXmm;

typedef struct InputOperandMemory {
  MemoryLocationType type;
  union {
    MemoryLocationInstructionPointerRelative instruction_pointer_relative;
    MemoryLocationIndirect                   indirect;
    MemoryLocationStack                      stack;
  };
} InputOperandMemory;

typedef struct InputOperand {
  InputOperandType type;
  union {
    InputOperandRegister  reg;
    InputOperandImmediate imm;
    InputOperandXmm       xmm;
    InputOperandMemory    memory;
  };
} InputOperand;

typedef struct InputInstruction {
  InputMnemonic mnemonic;
  const InputOperand operands[3];
  u8 operand_count;
} InputInstruction;

typedef enum REX_BYTE {
  REX   = 0b01000000,
  REX_W = 0b01001000, // 0 = Storage size determined by CS.D; 1 = 64 Bit Storage Size
  REX_R = 0b01000100, // Extension of the ModR/M reg field
  REX_X = 0b01000010, // Extension of the SIB index field
  REX_B = 0b01000001, // Extension of the ModR/M r/m field, SIB base field, or Opcode reg field
} REX_BYTE;

typedef enum MOD {
  MOD_Displacement_0   = 0b00,
  MOD_Displacement_s8  = 0b01,
  MOD_Displacement_s32 = 0b10,
  MOD_Register         = 0b11,
} MOD;

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

static int operand_compare(const InputOperand *a, const OperandEncoding *b) {
  switch (b->type) {
    case OPERAND_ENCODING_TYPE_REGISTER:
      return (a->type == INPUT_OPERAND_TYPE_REGISTER) &&
             (a->reg.size == b->size);
    case OPERAND_ENCODING_TYPE_REGISTER_A:
      return (a->type == INPUT_OPERAND_TYPE_REGISTER) &&
             (a->reg.type == INPUT_OPERAND_REGISTER_TYPE_A) &&
             (a->reg.size == b->size);
    case OPERAND_ENCODING_TYPE_REGISTER_OR_MEMORY:
      return ((a->type == INPUT_OPERAND_TYPE_REGISTER) &&
             (a->reg.size == b->size)) ||
             (a->type == INPUT_OPERAND_TYPE_MEMORY);
    case OPERAND_ENCODING_TYPE_IMMEDIATE:
      return (a->type == INPUT_OPERAND_TYPE_IMMEDIATE) &&
             (a->imm.size == b->size);
    case OPERAND_ENCODING_TYPE_MEMORY:
      return (a->type == INPUT_OPERAND_TYPE_MEMORY);
    case OPERAND_ENCODING_TYPE_XMM:
      return (a->type == INPUT_OPERAND_TYPE_XMM) &&
             (a->xmm.size == b->size);
  }
}

static void print_bytes(const u8 *bytes, u8 length) {
  asm volatile(
      "syscall"
    :
    : "a"(1), "S"(bytes), "d"(length), "D"(1)
    : "memory", "rcx", "r11"
  );
  /*
  for (u8 i = length; i > 0; i--) {
    asm("movl $1,%eax;"
        "mov %"
        "xorl %ebx,%ebx;"
        "int  $0x80"
    );
    //printf("%02X ", bytes[length-i]);
  }
   */
}

static void print_byte(u8 bytes) {
  print_bytes(&bytes, 1);
}


static void encode(const InputInstruction *ins) {
  // FIXME find mnemonic by name
  const Mnemonic *mnemonic = &mov;
  const InstructionEncoding *encodings[32];
  int matched_encodings = 0;
  for (int i = 0; i < mnemonic->encoding_count; i++) {
    const InstructionEncoding *encoding = &mnemonic->encodings[i];
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
    //FIXME error: no valid encodings found
    return;
  }

  for (int i = 0; i < matched_encodings; i++) {
    const InstructionEncoding *encoding = encodings[i];

    u8 op_code[4] = {
        encoding->op_code[0],
        encoding->op_code[1],
        encoding->op_code[2],
        encoding->op_code[3],
    };
    int need_16b_prefix = 0;
    int need_sib = 0;
    u8 sib_byte = 0;
    u8 rex_byte = 0;
    u8 reg_or_op_code = 0;
    s8 mod_r_m_storage_index = -1;
    u8 r_m = 0;
    s32 disp = 0;
    MOD mod = MOD_Register;

    for (u8 j = 0; j < encoding->operand_count; j++) {
      const InputOperand    *input_op    = &ins->operands[j];
      const OperandEncoding *encoding_op = &encoding->operands[j];

      if (encoding_op->size == S16) {
        need_16b_prefix = 1;
      }

      if (encoding_op->size == S64 &&
          encoding_op->type != OPERAND_ENCODING_TYPE_XMM) {
        rex_byte |= REX_W;
      }

      if (input_op->type == INPUT_OPERAND_TYPE_REGISTER) {
        if (input_op->reg.size == S8) {
          // These registers are inaccessible in 32bit mode and AH, BH, CH, and DH
          // are targeted instead. To solve this we force REX prefix.
          // TODO: 32bit mode? look into this
          if (input_op->reg.type == INPUT_OPERAND_REGISTER_TYPE_SI ||
              input_op->reg.type == INPUT_OPERAND_REGISTER_TYPE_DI ||
              input_op->reg.type == INPUT_OPERAND_REGISTER_TYPE_SP ||
              input_op->reg.type == INPUT_OPERAND_REGISTER_TYPE_BP) {
            rex_byte |= REX;
          }
        }

        if (encoding_op->type == OPERAND_ENCODING_TYPE_REGISTER) {
          if (encoding->extension == INSTRUCTION_EXTENSION_TYPE_PLUS_REGISTER) {
            op_code[3] += input_op->reg.type & 0b111;
            if (input_op->reg.type & 0b1000) {
              rex_byte |= REX_B;
            }
          } else {
            // assert(encoding->extension != INSTRUCTION_EXTENSION_TYPE_OP_CODE); // TODO: why?
            reg_or_op_code = (u8)input_op->reg.type;
            if (input_op->reg.type & 0b1000) {
              rex_byte |= REX_R;
            }
          }
        }
      }

      if (input_op->type == INPUT_OPERAND_TYPE_XMM &&
          encoding_op->type == OPERAND_ENCODING_TYPE_XMM &&
          encoding->extension == INSTRUCTION_EXTENSION_TYPE_REGISTER) {
        reg_or_op_code = (u8)input_op->xmm.type;
      }

      if (encoding_op->type == OPERAND_ENCODING_TYPE_MEMORY ||
          encoding_op->type == OPERAND_ENCODING_TYPE_REGISTER_OR_MEMORY) {
        if (mod_r_m_storage_index != -1) {
          //FIXME Multiple MOD R/M operands are not supported in an instruction
          return;
        }
        mod_r_m_storage_index = j;
        switch(input_op->type) {
          case INPUT_OPERAND_TYPE_REGISTER:
            r_m = (u8)input_op->reg.type;
            mod = MOD_Register;
            break;
          case INPUT_OPERAND_TYPE_XMM:
            r_m = (u8)input_op->xmm.type;
            mod = MOD_Register;
            break;
          case INPUT_OPERAND_TYPE_MEMORY:;
            const InputOperandMemory *location = &input_op->memory;
            int can_have_zero_displacement = 1;
            enum { SIB_INDEX_NONE = 0b100,};
            switch (location->type) {
              case MEMORY_LOCATION_TYPE_INSTRUCTION_POINTER_RELATIVE:
                r_m = 0b0101;
                mod = 0b00;
                break;
              case MEMORY_LOCATION_TYPE_INDIRECT:;
                ScalingFactor sib_scale_bits = SCALING_FACTOR_1;
                InputOperandRegisterType base = location->indirect.base_register;

                if (location->indirect.has_index) {
                  sib_scale_bits = location->indirect.scale;
                  need_sib = 1;
                  r_m = 0b0100;
                  InputOperandRegisterType sib_index = location->indirect.index;
                  sib_byte = (
                    ((sib_scale_bits & 0b011) << 6) |
                    ((sib_index      & 0b111) << 3) |
                    ((base           & 0b111) << 0)
                  );
                  if (sib_index & 0b1000) {
                    rex_byte |= REX_X;
                  }
                } else if (base == INPUT_OPERAND_REGISTER_TYPE_SP ||
                           base == INPUT_OPERAND_REGISTER_TYPE_12) {
                  // [RSP + X] and [R12 + X] always needs to be encoded as SIB because
                  // 0b100 register index in MOD R/M is occupied by SIB byte indicator
                  need_sib = 1;
                  r_m = 0b0100;
                  sib_byte = (
                      ((sib_scale_bits & 0b11) << 6) |
                      ((SIB_INDEX_NONE & 0b111) << 3) |
                      ((base & 0b111) << 0)
                  );
                } else {
                  r_m = base;
                }

                // 0b101 value is occupied RIP-relative encoding indicator
                // when mod is 00, so for the (RBP / R13) always use disp8 (mod 01)
                if (base == INPUT_OPERAND_REGISTER_TYPE_BP ||
                    base == INPUT_OPERAND_REGISTER_TYPE_13) {
                  can_have_zero_displacement = 0;
                }
                disp = location->indirect.offset;
                if (can_have_zero_displacement && disp == 0) {
                  mod = MOD_Displacement_0;
                } else if (INT8_MIN <= disp && disp <= INT8_MAX) {
                  mod = MOD_Displacement_s8;
                } else {
                  mod = MOD_Displacement_s32;
                }
                break;
              case MEMORY_LOCATION_TYPE_STACK:
                need_sib = 1;
                r_m = 0b0100;
                sib_byte = (((SIB_INDEX_NONE & 0b111) << 3) | INPUT_OPERAND_REGISTER_TYPE_SP);
                mod = MOD_Displacement_s32;
                break;
            }
            break;
          case INPUT_OPERAND_TYPE_IMMEDIATE:
            // FIXME error: encoding type is register or memory, but input is imm
            return;
        }
      }
    }

    if (encoding->extension == INSTRUCTION_EXTENSION_TYPE_OP_CODE) {
      reg_or_op_code = encoding->op_code_extension;
    }

    if (r_m & 0b1000) {
      rex_byte |= REX_B;
    }

    if (need_16b_prefix) {
      print_byte(0x66);
    }

    if (rex_byte) {
      print_byte(rex_byte);
    }

    for (int j = 0; j < 4; j++) {
      if (j == 3 || op_code[j]) {
        print_byte(op_code[j]);
      }
    }
    //TODO: stack patch?

    if (mod_r_m_storage_index != -1) {
      u8 mod_r_m = (
        (mod << 6) |
        ((reg_or_op_code & 0b111) << 3) |
        ((r_m & 0b111))
      );
      print_byte(mod_r_m);
    }

    if (need_sib) {
      print_byte(sib_byte);
    }

    if (mod_r_m_storage_index != -1 && mod != MOD_Register) {
      const InputOperand *input_op = &ins->operands[mod_r_m_storage_index];
      //assert(input_op->type == INPUT_OPERAND_TYPE_MEMORY);
      const InputOperandMemory *location = &input_op->memory;
      switch (location->type) {
        case MEMORY_LOCATION_TYPE_INSTRUCTION_POINTER_RELATIVE:
          //FIXME implement this
          return;
        case MEMORY_LOCATION_TYPE_INDIRECT:
          switch (mod) {
            case MOD_Displacement_s32:
              print_bytes((u8*)&disp, 4);
              break;
            case MOD_Displacement_s8:;
              print_byte((u8)disp);
              break;
            default:
              break;
          }
          break;
        case MEMORY_LOCATION_TYPE_STACK:
          // FIXME: stack patch?
          print_bytes((u8*)&location->stack.offset, 4);
          break;
      }
    }

    for (u32 j = 0; j < encoding->operand_count; j++) {
      const OperandEncoding *op_encoding = &encoding->operands[j];
      if (op_encoding->type != OPERAND_ENCODING_TYPE_IMMEDIATE)
        continue;
      const InputOperand *input_op = &ins->operands[j];
      if (input_op->type == INPUT_OPERAND_TYPE_MEMORY &&
          input_op->memory.type == MEMORY_LOCATION_TYPE_INSTRUCTION_POINTER_RELATIVE) {
        //FIXME implement this
        return;
      } else if (input_op->type == INPUT_OPERAND_TYPE_IMMEDIATE) {
        print_bytes((u8*)&input_op->imm.value, input_op->imm.size / 8);
      } else {
        // FIXME Unexpected mismatched operand type for immediate encoding.
        return;
      }
    }

    // TODO: label patches?
    //printf("\n");
  }
}


#define INSTRUCTION(_mnemonic, ...) { \
    .mnemonic=(_mnemonic),              \
    .operands={__VA_ARGS__},            \
    .operand_count=countof((InputOperand[]){__VA_ARGS__}),\
  }

#define RAX {.type=INPUT_OPERAND_TYPE_REGISTER, .reg={.type=INPUT_OPERAND_REGISTER_TYPE_A,  .size=S64}}
#define RCX {.type=INPUT_OPERAND_TYPE_REGISTER, .reg={.type=INPUT_OPERAND_REGISTER_TYPE_C,  .size=S64}}
#define RDX {.type=INPUT_OPERAND_TYPE_REGISTER, .reg={.type=INPUT_OPERAND_REGISTER_TYPE_D,  .size=S64}}
#define RBX {.type=INPUT_OPERAND_TYPE_REGISTER, .reg={.type=INPUT_OPERAND_REGISTER_TYPE_B,  .size=S64}}
#define RSP {.type=INPUT_OPERAND_TYPE_REGISTER, .reg={.type=INPUT_OPERAND_REGISTER_TYPE_SP, .size=S64}}
#define RBP {.type=INPUT_OPERAND_TYPE_REGISTER, .reg={.type=INPUT_OPERAND_REGISTER_TYPE_BP, .size=S64}}
#define RSI {.type=INPUT_OPERAND_TYPE_REGISTER, .reg={.type=INPUT_OPERAND_REGISTER_TYPE_SI, .size=S64}}
#define RDI {.type=INPUT_OPERAND_TYPE_REGISTER, .reg={.type=INPUT_OPERAND_REGISTER_TYPE_DI, .size=S64}}
#define R8  {.type=INPUT_OPERAND_TYPE_REGISTER, .reg={.type=INPUT_OPERAND_REGISTER_TYPE_8,  .size=S64}}
#define R9  {.type=INPUT_OPERAND_TYPE_REGISTER, .reg={.type=INPUT_OPERAND_REGISTER_TYPE_9,  .size=S64}}
#define R10 {.type=INPUT_OPERAND_TYPE_REGISTER, .reg={.type=INPUT_OPERAND_REGISTER_TYPE_10, .size=S64}}
#define R11 {.type=INPUT_OPERAND_TYPE_REGISTER, .reg={.type=INPUT_OPERAND_REGISTER_TYPE_11, .size=S64}}
#define R12 {.type=INPUT_OPERAND_TYPE_REGISTER, .reg={.type=INPUT_OPERAND_REGISTER_TYPE_12, .size=S64}}
#define R13 {.type=INPUT_OPERAND_TYPE_REGISTER, .reg={.type=INPUT_OPERAND_REGISTER_TYPE_13, .size=S64}}
#define R14 {.type=INPUT_OPERAND_TYPE_REGISTER, .reg={.type=INPUT_OPERAND_REGISTER_TYPE_14, .size=S64}}
#define R15 {.type=INPUT_OPERAND_TYPE_REGISTER, .reg={.type=INPUT_OPERAND_REGISTER_TYPE_15, .size=S64}}

#define EAX  {.type=INPUT_OPERAND_TYPE_REGISTER, .reg={.type=INPUT_OPERAND_REGISTER_TYPE_A,  .size=S32}}
#define ECX  {.type=INPUT_OPERAND_TYPE_REGISTER, .reg={.type=INPUT_OPERAND_REGISTER_TYPE_C,  .size=S32}}
#define EDX  {.type=INPUT_OPERAND_TYPE_REGISTER, .reg={.type=INPUT_OPERAND_REGISTER_TYPE_D,  .size=S32}}
#define EBX  {.type=INPUT_OPERAND_TYPE_REGISTER, .reg={.type=INPUT_OPERAND_REGISTER_TYPE_B,  .size=S32}}
#define ESP  {.type=INPUT_OPERAND_TYPE_REGISTER, .reg={.type=INPUT_OPERAND_REGISTER_TYPE_SP, .size=S32}}
#define EBP  {.type=INPUT_OPERAND_TYPE_REGISTER, .reg={.type=INPUT_OPERAND_REGISTER_TYPE_BP, .size=S32}}
#define ESI  {.type=INPUT_OPERAND_TYPE_REGISTER, .reg={.type=INPUT_OPERAND_REGISTER_TYPE_SI, .size=S32}}
#define EDI  {.type=INPUT_OPERAND_TYPE_REGISTER, .reg={.type=INPUT_OPERAND_REGISTER_TYPE_DI, .size=S32}}
#define R8D  {.type=INPUT_OPERAND_TYPE_REGISTER, .reg={.type=INPUT_OPERAND_REGISTER_TYPE_8,  .size=S32}}
#define R9D  {.type=INPUT_OPERAND_TYPE_REGISTER, .reg={.type=INPUT_OPERAND_REGISTER_TYPE_9,  .size=S32}}
#define R10D {.type=INPUT_OPERAND_TYPE_REGISTER, .reg={.type=INPUT_OPERAND_REGISTER_TYPE_10, .size=S32}}
#define R11D {.type=INPUT_OPERAND_TYPE_REGISTER, .reg={.type=INPUT_OPERAND_REGISTER_TYPE_11, .size=S32}}
#define R12D {.type=INPUT_OPERAND_TYPE_REGISTER, .reg={.type=INPUT_OPERAND_REGISTER_TYPE_12, .size=S32}}
#define R13D {.type=INPUT_OPERAND_TYPE_REGISTER, .reg={.type=INPUT_OPERAND_REGISTER_TYPE_13, .size=S32}}
#define R14D {.type=INPUT_OPERAND_TYPE_REGISTER, .reg={.type=INPUT_OPERAND_REGISTER_TYPE_14, .size=S32}}
#define R15D {.type=INPUT_OPERAND_TYPE_REGISTER, .reg={.type=INPUT_OPERAND_REGISTER_TYPE_15, .size=S32}}

#define AX   {.type=INPUT_OPERAND_TYPE_REGISTER, .reg={.type=INPUT_OPERAND_REGISTER_TYPE_A,  .size=S16}}
#define CX   {.type=INPUT_OPERAND_TYPE_REGISTER, .reg={.type=INPUT_OPERAND_REGISTER_TYPE_C,  .size=S16}}
#define DX   {.type=INPUT_OPERAND_TYPE_REGISTER, .reg={.type=INPUT_OPERAND_REGISTER_TYPE_D,  .size=S16}}
#define BX   {.type=INPUT_OPERAND_TYPE_REGISTER, .reg={.type=INPUT_OPERAND_REGISTER_TYPE_B,  .size=S16}}
#define SP   {.type=INPUT_OPERAND_TYPE_REGISTER, .reg={.type=INPUT_OPERAND_REGISTER_TYPE_SP, .size=S16}}
#define BP   {.type=INPUT_OPERAND_TYPE_REGISTER, .reg={.type=INPUT_OPERAND_REGISTER_TYPE_BP, .size=S16}}
#define SI   {.type=INPUT_OPERAND_TYPE_REGISTER, .reg={.type=INPUT_OPERAND_REGISTER_TYPE_SI, .size=S16}}
#define DI   {.type=INPUT_OPERAND_TYPE_REGISTER, .reg={.type=INPUT_OPERAND_REGISTER_TYPE_DI, .size=S16}}
#define R8W  {.type=INPUT_OPERAND_TYPE_REGISTER, .reg={.type=INPUT_OPERAND_REGISTER_TYPE_8,  .size=S16}}
#define R9W  {.type=INPUT_OPERAND_TYPE_REGISTER, .reg={.type=INPUT_OPERAND_REGISTER_TYPE_9,  .size=S16}}
#define R10W {.type=INPUT_OPERAND_TYPE_REGISTER, .reg={.type=INPUT_OPERAND_REGISTER_TYPE_10, .size=S16}}
#define R11W {.type=INPUT_OPERAND_TYPE_REGISTER, .reg={.type=INPUT_OPERAND_REGISTER_TYPE_11, .size=S16}}
#define R12W {.type=INPUT_OPERAND_TYPE_REGISTER, .reg={.type=INPUT_OPERAND_REGISTER_TYPE_12, .size=S16}}
#define R13W {.type=INPUT_OPERAND_TYPE_REGISTER, .reg={.type=INPUT_OPERAND_REGISTER_TYPE_13, .size=S16}}
#define R14W {.type=INPUT_OPERAND_TYPE_REGISTER, .reg={.type=INPUT_OPERAND_REGISTER_TYPE_14, .size=S16}}
#define R15W {.type=INPUT_OPERAND_TYPE_REGISTER, .reg={.type=INPUT_OPERAND_REGISTER_TYPE_15, .size=S16}}

#define AL   {.type=INPUT_OPERAND_TYPE_REGISTER, .reg={.type=INPUT_OPERAND_REGISTER_TYPE_A,  .size=S8}}
#define CL   {.type=INPUT_OPERAND_TYPE_REGISTER, .reg={.type=INPUT_OPERAND_REGISTER_TYPE_C,  .size=S8}}
#define DL   {.type=INPUT_OPERAND_TYPE_REGISTER, .reg={.type=INPUT_OPERAND_REGISTER_TYPE_D,  .size=S8}}
#define BL   {.type=INPUT_OPERAND_TYPE_REGISTER, .reg={.type=INPUT_OPERAND_REGISTER_TYPE_B,  .size=S8}}
#define SPL  {.type=INPUT_OPERAND_TYPE_REGISTER, .reg={.type=INPUT_OPERAND_REGISTER_TYPE_SP, .size=S8}}
#define BPL  {.type=INPUT_OPERAND_TYPE_REGISTER, .reg={.type=INPUT_OPERAND_REGISTER_TYPE_BP, .size=S8}}
#define SIL  {.type=INPUT_OPERAND_TYPE_REGISTER, .reg={.type=INPUT_OPERAND_REGISTER_TYPE_SI, .size=S8}}
#define DIL  {.type=INPUT_OPERAND_TYPE_REGISTER, .reg={.type=INPUT_OPERAND_REGISTER_TYPE_DI, .size=S8}}
#define R8B  {.type=INPUT_OPERAND_TYPE_REGISTER, .reg={.type=INPUT_OPERAND_REGISTER_TYPE_8,  .size=S8}}
#define R9B  {.type=INPUT_OPERAND_TYPE_REGISTER, .reg={.type=INPUT_OPERAND_REGISTER_TYPE_9,  .size=S8}}
#define R10B {.type=INPUT_OPERAND_TYPE_REGISTER, .reg={.type=INPUT_OPERAND_REGISTER_TYPE_10, .size=S8}}
#define R11B {.type=INPUT_OPERAND_TYPE_REGISTER, .reg={.type=INPUT_OPERAND_REGISTER_TYPE_11, .size=S8}}
#define R12B {.type=INPUT_OPERAND_TYPE_REGISTER, .reg={.type=INPUT_OPERAND_REGISTER_TYPE_12, .size=S8}}
#define R13B {.type=INPUT_OPERAND_TYPE_REGISTER, .reg={.type=INPUT_OPERAND_REGISTER_TYPE_13, .size=S8}}
#define R14B {.type=INPUT_OPERAND_TYPE_REGISTER, .reg={.type=INPUT_OPERAND_REGISTER_TYPE_14, .size=S8}}
#define R15B {.type=INPUT_OPERAND_TYPE_REGISTER, .reg={.type=INPUT_OPERAND_REGISTER_TYPE_15, .size=S8}}

#define IMM8(v)  {INPUT_OPERAND_TYPE_IMMEDIATE, .imm={.value=(v), .size=S8}}
#define IMM16(v) {INPUT_OPERAND_TYPE_IMMEDIATE, .imm={.value=(v), .size=S16}}
#define IMM32(v) {INPUT_OPERAND_TYPE_IMMEDIATE, .imm={.value=(v), .size=S32}}
#define IMM64(v) {INPUT_OPERAND_TYPE_IMMEDIATE, .imm={.value=(v), .size=S64}}

__attribute__((force_align_arg_pointer))
void _start() {

  print_bytes("foo bar baz\n", 12);

  InputInstruction ins = INSTRUCTION(MOV, CX,  {
                                                    INPUT_OPERAND_TYPE_MEMORY,
                                                    .memory={
                                                        .type=MEMORY_LOCATION_TYPE_INDIRECT,
                                                        .indirect = {
                                                            .base_register = INPUT_OPERAND_REGISTER_TYPE_A,
                                                            .has_index = 1,
                                                            .index = INPUT_OPERAND_REGISTER_TYPE_15,
                                                            .scale = SCALING_FACTOR_4,
                                                            .offset = 0x1234,
                                                        }
                                                    }
                                                });
  encode(&ins);

  /* exit system call */
  asm("movl $1,%eax;"
      "xorl %ebx,%ebx;"
      "int  $0x80"
  );
  __builtin_unreachable();  // tell the compiler to make sure side effects are done before the asm statement
}
