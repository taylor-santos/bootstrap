#include <stdint.h>

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

typedef int8_t  s8;
typedef int16_t s16;
typedef int32_t s32;
typedef int64_t s64;

typedef enum EncodingExtensionModRMMod {
  ENCODING_EXTENSION_MODRM_MOD_OP_0 = 0,
  ENCODING_EXTENSION_MODRM_MOD_OP_1,
  ENCODING_EXTENSION_MODRM_MOD_OP_2,
  ENCODING_EXTENSION_MODRM_MOD_OP_3,
  ENCODING_EXTENSION_MODRM_MOD_REG,
} EncodingExtensionModRMMod;

typedef enum EncodingExtensionModRMReg {
  ENCODING_EXTENSION_MODRM_REG_0 = 0b000,
  ENCODING_EXTENSION_MODRM_REG_1 = 0b001,
  ENCODING_EXTENSION_MODRM_REG_2 = 0b010,
  ENCODING_EXTENSION_MODRM_REG_3 = 0b011,
  ENCODING_EXTENSION_MODRM_REG_4 = 0b100,
  ENCODING_EXTENSION_MODRM_REG_5 = 0b101,
  ENCODING_EXTENSION_MODRM_REG_6 = 0b110,
  ENCODING_EXTENSION_MODRM_REG_7 = 0b111,
  ENCODING_EXTENSION_MODRM_REG_OP_0,
  ENCODING_EXTENSION_MODRM_REG_OP_1,
  ENCODING_EXTENSION_MODRM_REG_OP_2,
} EncodingExtensionModRMReg;

typedef enum EncodingExtensionModRMRM {
  ENCODING_EXTENSION_MODRM_R_M_OP_0 = 0,
  ENCODING_EXTENSION_MODRM_R_M_OP_1,
  ENCODING_EXTENSION_MODRM_R_M_OP_2,
  ENCODING_EXTENSION_MODRM_R_M_OP_3,
} EncodingExtensionModRMRM;

typedef struct EncodingExtensionModRM {
  EncodingExtensionModRMMod mod;
  EncodingExtensionModRMReg reg;
  EncodingExtensionModRMRM  r_m;
} EncodingExtensionModRM;

typedef struct EncodingExtensionPrefix {
  u8 value;
} EncodingExtensionPrefix;

typedef struct EncodingExtensionPlusR {
  u8 reg;
} EncodingExtensionPlusR;

typedef enum EncodingExtensionType {
  ENCODING_EXTENSION_TYPE_NONE = 1,
  ENCODING_EXTENSION_TYPE_MOD_RM,
  ENCODING_EXTENSION_TYPE_PREFIX,
  ENCODING_EXTENSION_TYPE_PLUS_R,
} EncodingExtensionType;

typedef struct EncodingExtension {
  EncodingExtensionType type;
  union {
    EncodingExtensionModRM  mod_rm;
    EncodingExtensionPrefix prefix;
    EncodingExtensionPlusR  plus_r;
  };
} EncodingExtension;

typedef enum EncodingOperandType {
  ENCODING_OPERAND_TYPE_REGISTER = 1,
  ENCODING_OPERAND_TYPE_REGISTER_A,
  ENCODING_OPERAND_TYPE_REGISTER_CL,
  ENCODING_OPERAND_TYPE_MEMORY,
  ENCODING_OPERAND_TYPE_REL,
  ENCODING_OPERAND_TYPE_MOFFS,
  ENCODING_OPERAND_TYPE_IMMEDIATE,
  ENCODING_OPERAND_TYPE_1,
  ENCODING_OPERAND_TYPE_3,
} EncodingOperandType;

typedef enum StorageSize {
  S8  = 8,
  S16 = 16,
  S32 = 32,
  S64 = 64,
} StorageSize;

typedef struct EncodingOperand {
  EncodingOperandType type;
  union {
    StorageSize reg_size;
    StorageSize imm_size;
    StorageSize rel_size;
  };
} EncodingOperand;

typedef struct EncodingInstruction {
  u8                op_code[4];
  u8                rex_w : 1;
  EncodingExtension extension;

  EncodingOperand   operands[4];
  u8                operand_count;
} EncodingInstruction;

typedef struct Instruction {
  const char                *mnemonic;
  const EncodingInstruction *encodings;
  u64                        encoding_count;
} Instruction;

#define countof(...)\
  (sizeof((__VA_ARGS__)) / sizeof(*(__VA_ARGS__)))

#ifndef __CLION_IDE__
#include "instructions.h"
#endif

typedef enum FileFlags {
  O_RDONLY    = 00000000,
  O_WRONLY    = 00000001,
  O_RDWR      = 00000002,
  O_CREAT     = 00000100,
  O_EXCL      = 00000200,
  O_NOCTTY    = 00000400,
  O_TRUNC     = 00001000,
  O_APPEND    = 00002000,
  O_NONBLOCK  = 00004000,
  O_SYNC      = 00010000,
  FASYNC      = 00020000,
  O_DIRECT    = 00040000,
  O_LARGEFILE = 00100000,
  O_DIRECTORY = 00200000,
  O_NOFOLLOW  = 00400000,
  O_NOATIME   = 01000000,
  O_CLOEXEC   = 02000000,
  O_NDELAY    = O_NONBLOCK
} FileFlags;

typedef enum FileMode {
  S_NONE  = 00000,
  S_IRWXU = 00700,   // user (file owner) has read, write, and execute permission
  S_IRUSR = 00400,   // user has read permission
  S_IWUSR = 00200,   // user has write permission
  S_IXUSR = 00100,   // user has execute permission
  S_IRWXG = 00070,   // group has read, write, and execute permission
  S_IRGRP = 00040,   // group has read permission
  S_IWGRP = 00020,   // group has write permission
  S_IXGRP = 00010,   // group has execute permission
  S_IRWXO = 00007,   // others have read, write, and execute permission
  S_IROTH = 00004,   // others have read permission
  S_IWOTH = 00002,   // others have write permission
  S_IXOTH = 00001,   // others have execute permission
  S_ISUID = 0004000, // set-user-ID bit
  S_ISGID = 0002000, // set-group-ID bit (see inode(7)).
  S_ISVTX = 0001000, // sticky bit (see inode(7)).
} FileMode;

int strncmp(const char *s1, const char *s2, int n);
u64 read(int fd, void *buf, u64 len);
int open(const char *filename, FileFlags flags, FileMode mode);
int close(int fd);
void exit(int code);
void *brk(void *ptr);
void *bsearch(const void *key, const void *base0, u64 nmemb, u64 size,
              int (*compar)(const void *, const void *));
int strcmp(const char *a, const char *b);


#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)
#define AT __FILE__ ":" TOSTRING(__LINE__)
#define print(msg) print_bytes((msg), sizeof(msg))
#define ICE(msg) print(AT ": ICE: " msg)
#define assert(cond) do { if(!(cond)) { print(AT ": assertion failed `" # cond "`\n"); exit(1); } } while(0)

typedef enum AssemblyOperandType {
  ASSEMBLY_OPERAND_TYPE_REGISTER = 1,
  ASSEMBLY_OPERAND_TYPE_HIGH_REGISTER,
  ASSEMBLY_OPERAND_TYPE_IMMEDIATE,
  ASSEMBLY_OPERAND_TYPE_MEMORY,
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
  MEMORY_INDEX_REGISTER_TYPE_A    = 0,
  MEMORY_INDEX_REGISTER_TYPE_C    = 1,
  MEMORY_INDEX_REGISTER_TYPE_D    = 2,
  MEMORY_INDEX_REGISTER_TYPE_B    = 3,
  MEMORY_INDEX_REGISTER_TYPE_NONE = 4, // RSP cannot be used as the index register
  MEMORY_INDEX_REGISTER_TYPE_BP   = 5,
  MEMORY_INDEX_REGISTER_TYPE_SI   = 6,
  MEMORY_INDEX_REGISTER_TYPE_DI   = 7,
  MEMORY_INDEX_REGISTER_TYPE_8    = 8,
  MEMORY_INDEX_REGISTER_TYPE_9    = 9,
  MEMORY_INDEX_REGISTER_TYPE_10   = 10,
  MEMORY_INDEX_REGISTER_TYPE_11   = 11,
  MEMORY_INDEX_REGISTER_TYPE_12   = 12,
  MEMORY_INDEX_REGISTER_TYPE_13   = 13,
  MEMORY_INDEX_REGISTER_TYPE_14   = 14,
  MEMORY_INDEX_REGISTER_TYPE_15   = 15,
} MemoryIndexRegisterType;

typedef enum MemoryLocationType {
  MEMORY_LOCATION_TYPE_INDIRECT = 1,
  MEMORY_LOCATION_TYPE_RELATIVE,
} MemoryLocationType;

typedef enum ScalingFactor {
  SCALING_FACTOR_1 = 0b00,
  SCALING_FACTOR_2 = 0b01,
  SCALING_FACTOR_4 = 0b10,
  SCALING_FACTOR_8 = 0b11,
} ScalingFactor;

typedef enum REXByte {
  REX   = 0b01000000,
  REX_W = 0b01001000, // 0 = Storage size determined by CS.D; 1 = 64 Bit Storage Size
  REX_R = 0b01000100, // Extension of the ModR/M reg field
  REX_X = 0b01000010, // Extension of the SIB index field
  REX_B = 0b01000001, // Extension of the ModR/M r/m field, SIB base field, or Opcode reg field
} REXByte;

typedef enum Mod {
  MOD_DISP0    = 0b00,
  MOD_DISP8    = 0b01,
  MOD_DISP32   = 0b10,
  MOD_REGISTER = 0b11,
} Mod;

typedef struct MemoryLocationIndirect {
  u8                          has_base;
  AssemblyOperandRegisterType base;
  MemoryIndexRegisterType     index;
  ScalingFactor               scale;
  s64                         disp;
} MemoryLocationIndirect;

typedef struct MemoryLocationRelative {
  s64 offset;
} MemoryLocationRelative;

typedef struct AssemblyOperandRegister {
  AssemblyOperandRegisterType type;
  StorageSize                 size;
} AssemblyOperandRegister;

typedef struct AssemblyOperandHighRegister {
  AssemblyOperandHighRegisterType type;
} AssemblyOperandHighRegister;

typedef struct AssemblyOperandImmediate {
  s64 value;
} AssemblyOperandImmediate;

typedef struct AssemblyOperandMemory {
  MemoryLocationType type;
  union {
    MemoryLocationIndirect indirect;
    MemoryLocationRelative relative;
  };
} AssemblyOperandMemory;

typedef struct AssemblyOperand {
  AssemblyOperandType type;
  union {
    AssemblyOperandRegister     reg;
    AssemblyOperandHighRegister high_reg;
    AssemblyOperandImmediate    imm;
    AssemblyOperandMemory       memory;
  };
} AssemblyOperand;

typedef struct AssemblyInstruction {
  const char            *mnemonic;
  const AssemblyOperand  operands[3];
  u8                     operand_count;
} AssemblyInstruction;

int fits_in(s64 value, StorageSize size) {
  switch (size) {
    case S8:
      return (INT8_MIN  <= value) && (value <= INT8_MAX);
    case S16:
      return (INT16_MIN <= value) && (value <= INT16_MAX);
    case S32:
      return (INT32_MIN <= value) && (value <= INT32_MAX);
    case S64:
      return (INT64_MIN <= value) && (value <= INT64_MAX);
  }
}

#define CASE(_case, _body) case _case: { _body; break; }

int operand_compare(const AssemblyOperand *a, const EncodingOperand *b) {
  switch (b->type) {
    case ENCODING_OPERAND_TYPE_REGISTER: {
      return ((a->type == ASSEMBLY_OPERAND_TYPE_REGISTER) &&
              (a->reg.size == b->reg_size)) ||
             ((a->type == ASSEMBLY_OPERAND_TYPE_HIGH_REGISTER) &&
              (b->reg_size == S8));
    }
    case ENCODING_OPERAND_TYPE_REGISTER_A: {
      return (a->type == ASSEMBLY_OPERAND_TYPE_REGISTER) &&
             (a->reg.type == ASSEMBLY_OPERAND_REGISTER_TYPE_A) &&
             (a->reg.size == b->reg_size);
    }
    case ENCODING_OPERAND_TYPE_REGISTER_CL: {
      return (a->type == ASSEMBLY_OPERAND_TYPE_REGISTER) &&
             (a->reg.type == ASSEMBLY_OPERAND_REGISTER_TYPE_C) &&
             (a->reg.size == S8);
    }
    case ENCODING_OPERAND_TYPE_MEMORY: {
      return (a->type == ASSEMBLY_OPERAND_TYPE_MEMORY) &&
             (a->memory.type == MEMORY_LOCATION_TYPE_INDIRECT) &&
             fits_in(a->memory.indirect.disp, S32);
    }
    case ENCODING_OPERAND_TYPE_REL: {
      return (a->type == ASSEMBLY_OPERAND_TYPE_MEMORY) &&
             (a->memory.type == MEMORY_LOCATION_TYPE_RELATIVE) &&
             fits_in(a->memory.relative.offset, b->rel_size);
    }
    case ENCODING_OPERAND_TYPE_MOFFS: {
      return (a->type == ASSEMBLY_OPERAND_TYPE_MEMORY) &&
             (a->memory.type == MEMORY_LOCATION_TYPE_INDIRECT) &&
             (a->memory.indirect.has_base == 0) &&
             (a->memory.indirect.index == MEMORY_INDEX_REGISTER_TYPE_NONE);
    }
    case ENCODING_OPERAND_TYPE_IMMEDIATE: {
      return (a->type == ASSEMBLY_OPERAND_TYPE_IMMEDIATE) &&
             (fits_in(a->imm.value, b->imm_size));
    }
    case ENCODING_OPERAND_TYPE_1: {
      return (a->type == ASSEMBLY_OPERAND_TYPE_IMMEDIATE) &&
             (a->imm.value == 1);
    }
    case ENCODING_OPERAND_TYPE_3: {
      return (a->type == ASSEMBLY_OPERAND_TYPE_IMMEDIATE) &&
             (a->imm.value == 3);
    }
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

typedef enum VEXPrefix {
  VEX_PREFIX_NONE   = 0,
  VEX_PREFIX_3B_VEX = 0xC4,
  VEX_PREFIX_2B_VEX = 0xC5,
  VEX_PREFIX_3B_XOP = 0x8F,
} VEXPrefix;

typedef enum VEXpp {
  VEX_pp_NONE = 0b00,
  VEX_pp_0x66 = 0b01,
  VEX_pp_0xF3 = 0b10,
  VEX_pp_0xF2 = 0b11,
} VEXpp;

typedef struct VEX {
  u8        map_select : 5;
  u8        B          : 1;
  u8        X          : 1;
  u8        R          : 1;
  VEXpp     pp         : 2;
  u8        L          : 1;
  u8        vvvv       : 4;
  u8        W_E        : 1;
  VEXPrefix prefix     : 8;
} VEX;

typedef struct ModRM {
  u8  r_m : 3;
  u8  reg : 3;
  Mod mod : 2;
} ModRM;

typedef struct SIB {
  u8 scale : 2;
  u8 index : 3;
  u8 base  : 3;
} SIB;

typedef struct EncodingResult {
  EncodingPrefix prefix : 8;
  u8             rex;
  VEX            vex;
  u8             op_code[4];
  s8             mod_rm_needed;
  ModRM          mod_rm;
  SIB            sib;
  u8             disp_bytes;
  s64            disp;
  u8             imm_bytes;
  u64            imm;
} EncodingResult;

int
print_encoding(const EncodingResult *encoding, u8 *output) {
  int i = 0;
  if (encoding->prefix != 0) {
    output[i++] = encoding->prefix;
  }
  if (encoding->rex) {
    output[i++] = encoding->rex;
  }
  switch (encoding->vex.prefix) {
    case VEX_PREFIX_3B_VEX:
    case VEX_PREFIX_3B_XOP: {
      output[i++] = encoding->vex.prefix;
      output[i++] = (
          ((encoding->vex.R          & 0b00001) << 7) |
          ((encoding->vex.X          & 0b00001) << 6) |
          ((encoding->vex.B          & 0b00001) << 5) |
          ((encoding->vex.map_select & 0b11111) << 0)
      );
      output[i++] = (
          ((encoding->vex.W_E  & 0b0001) << 7) |
          ((encoding->vex.vvvv & 0b1111) << 3) |
          ((encoding->vex.L    & 0b0001) << 2) |
          ((encoding->vex.pp   & 0b0011) << 0)
      );
      break;
    }
    case VEX_PREFIX_2B_VEX: {
      break;
    }
    case VEX_PREFIX_NONE:
      break;
  }
  for (int j = 0; j < countof(encoding->op_code); j++) {
    if (encoding->op_code[j] != 0) {
      output[i++] = encoding->op_code[j];
    }
  }
  if (encoding->mod_rm_needed) {
    output[i++] = (
      ((encoding->mod_rm.mod & 0b011) << 6) |
      ((encoding->mod_rm.reg & 0b111) << 3) |
      ((encoding->mod_rm.r_m & 0b111) << 0)
    );

    // SIB
    if ((encoding->mod_rm.r_m == 0b100) &&
        (encoding->mod_rm.mod != 0b11)) {
      output[i++] = (
        ((encoding->sib.scale & 0b011) << 6) |
        ((encoding->sib.index & 0b111) << 3) |
        ((encoding->sib.base  & 0b111) << 0)
      );
    }
  }
  for (int j = 0; j < encoding->disp_bytes; j++) {
    output[i++] = ((u8*)&encoding->disp)[j];
  }
  for (int j = 0; j < encoding->imm_bytes; j++) {
    output[i++] = ((u8*)&encoding->imm)[j];
  }
  return i;
}

void
generate_sib(u8 has_base, u8 base, u8 scale, u8 index, s32 disp, EncodingResult *result) {
  result->mod_rm.r_m = 0b100;
  result->sib.scale = scale;
  result->sib.index = index;
  if (has_base) {
    if (disp == 0) {
      if (base == 0b101) {
        result->mod_rm.mod = MOD_DISP8;
        result->sib.base = 0b101;
        result->disp_bytes = 1;
        result->disp = 0;
      } else {
        result->mod_rm.mod = MOD_DISP0;
        result->sib.base = base;
        result->disp_bytes = 0;
        result->disp = 0;
      }
    } else if (fits_in(disp, S8)) {
      result->mod_rm.mod = MOD_DISP8;
      result->sib.base = base;
      result->disp_bytes = 1;
      result->disp = disp;
    } else {
      assert(fits_in(disp, S32));
      result->mod_rm.mod = MOD_DISP32;
      result->sib.base = base;
      result->disp_bytes = 4;
      result->disp = disp;
    }
  } else {
    /* 64-bit displacement-only mode can be enabled using Mod=00 and R/M=100,
     * which is normally SIB mode without a displacement. While Base=101
     * normally represents RBP, if Mod=00 then disp32 is enabled instead. Now,
     * Index=100 can be used to indicate no index is used, leaving just the
     * disp32.
     */
    result->mod_rm.mod = MOD_DISP0;
    result->sib.base = 0b101;
    result->disp_bytes = 4;
    result->disp = disp;
  }
}


void
indirect_memory(const MemoryLocationIndirect mem, EncodingResult *result) {
  if ((mem.index != MEMORY_INDEX_REGISTER_TYPE_NONE) ||
      (mem.has_base && ((mem.base & 0b111) == 0b100)) ||
      (!mem.has_base)) {
    /* There are 3 cases when a SIB byte are needed:
     * 1) The address includes an index and scale. These can only be encoded
     *    using a SIB byte.
     * 2) The address includes a base which ends in 0b100. The R/M bits are used
     *    to encode the base when a SIB byte is not used, or 0b100 to signal a
     *    SIB byte. If a SIB byte is otherwise unnecessary, but the base ends
     *    in 0b100, a SIB byte must be included.
     * 3) 64-bit displacement-only mode. In 32-bit mode, a displacement-only
     *    address can be encoded using just the MODR/M byte. But this same
     *    encoding is used in 64-bit mode for RIP-relative addressing. To
     *    encode only a displacement, a SIB byte must be included.
     */
    generate_sib(mem.has_base, mem.base & 0b111, mem.scale, mem.index & 0b111, mem.disp, result);
    if (is_extended_register(mem.index)) {
      result->rex |= REX_X;
    }
  } else {
    if (mem.disp == 0) {
      if ((mem.base & 0b111) == 0b101) {
        /* [rbp] and [r13] on their own cannot be encoded like the other
         * registers, because their encoding is occupied by the RIP-relative
         * addressing mode. Instead, they can be encoded with a 0-valued disp8.
         */
        result->mod_rm.mod = MOD_DISP8;
        result->mod_rm.r_m = 0b101;
        if (is_extended_register(mem.base)) {
          result->rex |= REX_B;
        }
        result->disp_bytes = 1;
        result->disp = 0;
      } else {
        result->mod_rm.mod = MOD_DISP0;
        result->mod_rm.r_m = mem.base & 0b111;
        if (is_extended_register(mem.base)) {
          result->rex |= REX_B;
        }
        result->disp_bytes = 0;
      }
    } else if (fits_in(mem.disp, S8)) {
      result->mod_rm.mod = MOD_DISP8;
      result->mod_rm.r_m = mem.base & 0b111;
      if (is_extended_register(mem.base)) {
        result->rex |= REX_B;
      }
      result->disp_bytes = 1;
      result->disp = mem.disp;
    } else {
      assert(fits_in(mem.disp, S32));
      result->mod_rm.mod = MOD_DISP32;
      result->mod_rm.r_m = mem.base & 0b111;
      if (is_extended_register(mem.base)) {
        result->rex |= REX_B;
      }
      result->disp_bytes = 4;
      result->disp = mem.disp;
    }
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

  if (encoding->rex_w) {
    result.rex |= REX_W;
  }

  switch (encoding->extension.type) {
    case ENCODING_EXTENSION_TYPE_NONE: {
      break;
    }
    case ENCODING_EXTENSION_TYPE_MOD_RM: {
      result.mod_rm_needed = 1;
      {
        /*
         * ModRM Mod Bits
         */
        if (encoding->extension.mod_rm.mod ==
            ENCODING_EXTENSION_MODRM_MOD_REG) {
          result.mod_rm.mod = MOD_REGISTER;
        } else {
          int index = encoding->extension.mod_rm.mod;
          assert(index < assembly->operand_count);
          assert(assembly->operands[index].type ==
                 ASSEMBLY_OPERAND_TYPE_MEMORY);
          assert(assembly->operands[index].memory.type ==
                 MEMORY_LOCATION_TYPE_INDIRECT);
        }
      }
      {
        /*
         * ModRM Reg Bits
         */
        int index =
            encoding->extension.mod_rm.reg - ENCODING_EXTENSION_MODRM_REG_OP_0;
        if (index < 0) {
          result.mod_rm.reg = encoding->extension.mod_rm.reg & 0b111;
        } else {
          assert(index < assembly->operand_count);
          assert(assembly->operands[index].type ==
                 ASSEMBLY_OPERAND_TYPE_REGISTER); // Verified for all non-extension instructions
          result.mod_rm.reg = assembly->operands[index].reg.type & 0b111;
          if (is_extended_register(assembly->operands[index].reg.type)) {
            result.rex |= REX_R;
          }
        }
      }
      {
        /*
         * ModRM R/M Bits
         */
        int index = encoding->extension.mod_rm.r_m;
        assert(index < assembly->operand_count);
        switch (assembly->operands[index].type) {
          case ASSEMBLY_OPERAND_TYPE_REGISTER: {
            result.mod_rm.r_m = assembly->operands[index].reg.type & 0b111;
            if (is_extended_register(assembly->operands[index].reg.type)) {
              result.rex |= REX_B;
            }
            break;
          }
          case ASSEMBLY_OPERAND_TYPE_HIGH_REGISTER: {
            result.mod_rm.r_m = assembly->operands[index].high_reg.type & 0b111;
            if (is_extended_register(assembly->operands[index].high_reg.type)) {
              result.rex |= REX_B;
            }
            break;
          }
          case ASSEMBLY_OPERAND_TYPE_MEMORY: {
            break;
          }
          case ASSEMBLY_OPERAND_TYPE_IMMEDIATE: {
            ICE("immediate operand found in ModRM's R/M slot\n");
          }
        }
      }
      break;
    }
    case ENCODING_EXTENSION_TYPE_PREFIX: {
      result.prefix = encoding->extension.prefix.value;
      break;
    }
    case ENCODING_EXTENSION_TYPE_PLUS_R: {
      int index = encoding->extension.plus_r.reg;
      assert(assembly->operands[index].type == ASSEMBLY_OPERAND_TYPE_REGISTER);
      result.op_code[3] += assembly->operands[index].reg.type & 0b111;
      break;
    }
  }

  for (int i = 0; i < encoding->operand_count; i++) {
    const EncodingOperand *op = &encoding->operands[i];

    switch (op->type) {
      case ENCODING_OPERAND_TYPE_REGISTER:
      case ENCODING_OPERAND_TYPE_REGISTER_A: {
        if (op->reg_size == S16) {
          result.prefix = ENCODING_PREFIX_OPERAND_SIZE_OVERRIDE;
        }
        break;
      }
      case ENCODING_OPERAND_TYPE_IMMEDIATE: {
        if (op->imm_size == S16) {
          result.prefix = ENCODING_PREFIX_OPERAND_SIZE_OVERRIDE;
        }
        assert(assembly->operands[i].type == ASSEMBLY_OPERAND_TYPE_IMMEDIATE);
        const AssemblyOperandImmediate *imm = &assembly->operands[i].imm;
        assert(fits_in(imm->value, op->imm_size));
        result.imm_bytes = op->imm_size / 8;
        result.imm = imm->value;
        break;
      }
      case ENCODING_OPERAND_TYPE_MOFFS: {
        assert(assembly->operands[i].type == ASSEMBLY_OPERAND_TYPE_MEMORY);
        const AssemblyOperandMemory  *mem = &assembly->operands[i].memory;
        assert(mem->type == MEMORY_LOCATION_TYPE_INDIRECT);
        const MemoryLocationIndirect *in = &mem->indirect;
        assert(in->has_base == 0);
        assert(in->index == MEMORY_INDEX_REGISTER_TYPE_NONE);
        result.disp = in->disp;
        result.disp_bytes = 8;
        break;
      }
      case ENCODING_OPERAND_TYPE_REL: {
        assert(assembly->operands[i].type == ASSEMBLY_OPERAND_TYPE_MEMORY);
        const AssemblyOperandMemory  *mem = &assembly->operands[i].memory;
        assert(mem->type == MEMORY_LOCATION_TYPE_RELATIVE);
        const MemoryLocationRelative *rel = &mem->relative;
        assert(fits_in(rel->offset, op->rel_size));
        result.disp = rel->offset;
        result.disp_bytes = op->rel_size / 8;
        break;
      }
      case ENCODING_OPERAND_TYPE_MEMORY: {
        assert(assembly->operands[i].type == ASSEMBLY_OPERAND_TYPE_MEMORY);
        const AssemblyOperandMemory  *mem = &assembly->operands[i].memory;
        assert(mem->type == MEMORY_LOCATION_TYPE_INDIRECT);
        const MemoryLocationIndirect *in = &mem->indirect;
        indirect_memory(*in, &result);
        break;
      }
      case ENCODING_OPERAND_TYPE_REGISTER_CL:
      case ENCODING_OPERAND_TYPE_1:
      case ENCODING_OPERAND_TYPE_3:
        break;
    }

    if (op->type == ENCODING_OPERAND_TYPE_IMMEDIATE) {
      assert(assembly->operands[i].type == ASSEMBLY_OPERAND_TYPE_IMMEDIATE);
      const AssemblyOperandImmediate *imm = &assembly->operands[i].imm;
      assert(fits_in(imm->value, op->imm_size));
      result.imm_bytes = op->imm_size / 8;
      result.imm = imm->value;
    } else if (op->type == ENCODING_OPERAND_TYPE_MOFFS) {
      assert(assembly->operands[i].type == ASSEMBLY_OPERAND_TYPE_MEMORY);
      const AssemblyOperandMemory  *mem = &assembly->operands[i].memory;
      assert(mem->type == MEMORY_LOCATION_TYPE_INDIRECT);
      const MemoryLocationIndirect *in = &mem->indirect;
      assert(in->has_base == 0);
      assert(in->index == MEMORY_INDEX_REGISTER_TYPE_NONE);
      result.disp = in->disp;
      result.disp_bytes = 8;
    } else if (op->type == ENCODING_OPERAND_TYPE_REL) {
      assert(assembly->operands[i].type == ASSEMBLY_OPERAND_TYPE_MEMORY);
      const AssemblyOperandMemory  *mem = &assembly->operands[i].memory;
      assert(mem->type == MEMORY_LOCATION_TYPE_RELATIVE);
      const MemoryLocationRelative *rel = &mem->relative;
      assert(fits_in(rel->offset, op->rel_size));
      result.disp = rel->offset;
      result.disp_bytes = op->rel_size / 8;
    }

    const AssemblyOperand *as = &assembly->operands[i];
    if (((as->type == ASSEMBLY_OPERAND_TYPE_REGISTER) &&
         (op->reg_size == S16)) ||
        ((as->type == ASSEMBLY_OPERAND_TYPE_HIGH_REGISTER) &&
         (op->reg_size == S16)) ||
        ((as->type == ASSEMBLY_OPERAND_TYPE_IMMEDIATE) &&
         (op->imm_size == S16))) {
      result.prefix = ENCODING_PREFIX_OPERAND_SIZE_OVERRIDE;
    }
  }

  return result;
}


#define ASSEMBLY(_mnemonic, ...) (const AssemblyInstruction){ \
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

#define IMM8(v)  {ASSEMBLY_OPERAND_TYPE_IMMEDIATE, .imm={.value=(v)}}
#define IMM16(v) {ASSEMBLY_OPERAND_TYPE_IMMEDIATE, .imm={.value=(v)}}
#define IMM32(v) {ASSEMBLY_OPERAND_TYPE_IMMEDIATE, .imm={.value=(v)}}
#define IMM64(v) {ASSEMBLY_OPERAND_TYPE_IMMEDIATE, .imm={.value=(v)}}

#define MEM_BASE_INDEX_SCALE_DISP(_base, _index, _scale, _disp) {              \
    .type=ASSEMBLY_OPERAND_TYPE_MEMORY,                                        \
    .memory={                                                                  \
      .type=MEMORY_LOCATION_TYPE_INDIRECT,                                     \
      .indirect = {                                                            \
        .has_base = 1,                                                         \
        .base = ASSEMBLY_OPERAND_REGISTER_TYPE_ ## _base,                      \
        .index = MEMORY_INDEX_REGISTER_TYPE_ ## _index,                        \
        .scale = SCALING_FACTOR_ ## _scale,                                    \
        .disp = _disp,                                                         \
    }}}
#define MEM_BASE_INDEX_DISP(_base, _index, _disp) {                            \
    .type=ASSEMBLY_OPERAND_TYPE_MEMORY,                                        \
    .memory={                                                                  \
      .type=MEMORY_LOCATION_TYPE_INDIRECT,                                     \
      .indirect = {                                                            \
        .has_base = 1,                                                         \
        .base = ASSEMBLY_OPERAND_REGISTER_TYPE_ ## _base,                      \
        .index = MEMORY_INDEX_REGISTER_TYPE_ ## _index,                        \
        .scale = SCALING_FACTOR_ ## 1,                                         \
        .disp = _disp,                                                         \
    }}}
#define MEM_BASE_INDEX_SCALE(_base, _index, _scale) {                          \
    .type=ASSEMBLY_OPERAND_TYPE_MEMORY,                                        \
    .memory={                                                                  \
      .type=MEMORY_LOCATION_TYPE_INDIRECT,                                     \
      .indirect = {                                                            \
        .has_base = 1,                                                         \
        .base = ASSEMBLY_OPERAND_REGISTER_TYPE_ ## _base,                      \
        .index = MEMORY_INDEX_REGISTER_TYPE_ ## _index,                        \
        .scale = SCALING_FACTOR_ ## _scale,                                    \
        .disp = 0,                                                             \
    }}}
#define MEM_BASE_INDEX(_base, _index) {                                        \
    .type=ASSEMBLY_OPERAND_TYPE_MEMORY,                                        \
    .memory={                                                                  \
      .type=MEMORY_LOCATION_TYPE_INDIRECT,                                     \
      .indirect = {                                                            \
        .has_base = 1,                                                         \
        .base = ASSEMBLY_OPERAND_REGISTER_TYPE_ ## _base,                      \
        .index = MEMORY_INDEX_REGISTER_TYPE_ ## _index,                        \
        .scale = SCALING_FACTOR_ ## 1,                                         \
        .disp = 0,                                                             \
    }}}
#define MEM_INDEX_SCALE_DISP(_index, _scale, _disp) {                          \
    .type=ASSEMBLY_OPERAND_TYPE_MEMORY,                                        \
    .memory={                                                                  \
      .type=MEMORY_LOCATION_TYPE_INDIRECT,                                     \
      .indirect = {                                                            \
        .has_base = 0,                                                         \
        .index = MEMORY_INDEX_REGISTER_TYPE_ ## _index,                        \
        .scale = SCALING_FACTOR_ ## _scale,                                    \
        .disp = _disp,                                                         \
    }}}
#define MEM_INDEX_DISP(_index, _disp) {                                        \
    .type=ASSEMBLY_OPERAND_TYPE_MEMORY,                                        \
    .memory={                                                                  \
      .type=MEMORY_LOCATION_TYPE_INDIRECT,                                     \
      .indirect = {                                                            \
        .has_base = 0,                                                         \
        .index = MEMORY_INDEX_REGISTER_TYPE_ ## _index,                        \
        .scale = SCALING_FACTOR_ ## 1,                                         \
        .disp = _disp,                                                         \
    }}}
#define MEM_INDEX_SCALE(_index, _scale) {                                      \
    .type=ASSEMBLY_OPERAND_TYPE_MEMORY,                                        \
    .memory={                                                                  \
      .type=MEMORY_LOCATION_TYPE_INDIRECT,                                     \
      .indirect = {                                                            \
        .has_base = 0,                                                         \
        .index = MEMORY_INDEX_REGISTER_TYPE_ ## _index,                        \
        .scale = SCALING_FACTOR_ ## _scale,                                    \
        .disp = 0,                                                             \
    }}}
#define MEM_INDEX(_index) {                                                    \
    .type=ASSEMBLY_OPERAND_TYPE_MEMORY,                                        \
    .memory={                                                                  \
      .type=MEMORY_LOCATION_TYPE_INDIRECT,                                     \
      .indirect = {                                                            \
        .has_base = 0,                                                         \
        .index = MEMORY_INDEX_REGISTER_TYPE_ ## _index,                        \
        .scale = SCALING_FACTOR_ ## 1,                                         \
        .disp = 0,                                                             \
    }}}
#define MEM_BASE_DISP(_base, _disp) {                                          \
    .type=ASSEMBLY_OPERAND_TYPE_MEMORY,                                        \
    .memory={                                                                  \
      .type=MEMORY_LOCATION_TYPE_INDIRECT,                                     \
      .indirect = {                                                            \
        .has_base = 1,                                                         \
        .base = ASSEMBLY_OPERAND_REGISTER_TYPE_ ## _base,                      \
        .index = MEMORY_INDEX_REGISTER_TYPE_NONE,                              \
        .scale = SCALING_FACTOR_1,                                             \
        .disp = _disp,                                                         \
    }}}
#define MEM_BASE(_base) {                                                      \
    .type=ASSEMBLY_OPERAND_TYPE_MEMORY,                                        \
    .memory={                                                                  \
      .type=MEMORY_LOCATION_TYPE_INDIRECT,                                     \
      .indirect = {                                                            \
        .has_base = 1,                                                         \
        .base = ASSEMBLY_OPERAND_REGISTER_TYPE_ ## _base,                      \
        .index = MEMORY_INDEX_REGISTER_TYPE_NONE,                              \
        .scale = SCALING_FACTOR_1,                                             \
        .disp = 0,                                                             \
    }}}
#define MEM_DISP(_disp) {                                                      \
    .type=ASSEMBLY_OPERAND_TYPE_MEMORY,                                        \
    .memory={                                                                  \
      .type=MEMORY_LOCATION_TYPE_INDIRECT,                                     \
      .indirect = {                                                            \
        .has_base = 0,                                                         \
        .index = MEMORY_INDEX_REGISTER_TYPE_NONE,                              \
        .scale = SCALING_FACTOR_1,                                             \
        .disp = _disp,                                                         \
    }}}
#define MEM_INDEX_DISP(_index, _disp) {                                        \
    .type=ASSEMBLY_OPERAND_TYPE_MEMORY,                                        \
    .memory={                                                                  \
      .type=MEMORY_LOCATION_TYPE_INDIRECT,                                     \
      .indirect = {                                                            \
        .has_base = 0,                                                         \
        .index = MEMORY_INDEX_REGISTER_TYPE_ ## _index,                        \
        .scale = SCALING_FACTOR_ ## 1,                                         \
        .disp = _disp,                                                         \
    }}}
#define MEM() {                                                                \
    .type=ASSEMBLY_OPERAND_TYPE_MEMORY,                                        \
    .memory={                                                                  \
      .type=MEMORY_LOCATION_TYPE_INDIRECT,                                     \
      .indirect = {                                                            \
        .has_base = 0,                                                         \
        .index = MEMORY_INDEX_REGISTER_TYPE_NONE,                              \
        .scale = SCALING_FACTOR_1,                                             \
        .disp = 0,                                                             \
    }}}
#define MEM_REL(_offset) {                                                     \
    .type=ASSEMBLY_OPERAND_TYPE_MEMORY,                                        \
    .memory={                                                                  \
      .type=MEMORY_LOCATION_TYPE_RELATIVE,                                     \
      .relative = {                                                            \
        .offset = _offset,                                                     \
    }}}

const u64 brkinc = 4096;

u64
read_to_heap(int fd, void *heap) {
  u64 total = 0;
  while (1) {
    void *new_heap = brk(heap + brkinc);
    u64 len = read(fd, heap, brkinc);
    total += len;
    if (len < brkinc) break;
    heap = new_heap;
  }
  return total;
}

int cmp_instruction(const char *name, const Instruction *instruction) {
  return strcmp(name, instruction->mnemonic);
}

int main(int argc, const char **argv) {

  asm("bextr $0x12345678, %rdx, %rcx");

  if (argc != 3) {
    print("usage: ./c_assembler <input file> <output file>\n");
    return 1;
  }

  int input = open(argv[1], O_RDONLY, S_NONE);
  if (input < 0) {
    print("failed to open file\n");
    return 1;
  }

  void *brk_start = brk(0);
  int input_len = read_to_heap(input, brk_start);

  close(input);

  const AssemblyInstruction *ins =
      &ASSEMBLY(
        "jmp",
        MEM_REL(0x12),
      );

  const Instruction *instruction = bsearch(
    ins->mnemonic,
    instructions,
    countof(instructions),
    sizeof(*instructions),
    (int(*)(const void*, const void*))cmp_instruction
  );

  if (!instruction) {
    print("error: unknown mnemonic\n");
    return 1;
  }

  const EncodingInstruction *encodings[32];
  int matched_encodings = 0;
  for (int i = 0; i < instruction->encoding_count; i++) {
    const EncodingInstruction *encoding = &instruction->encodings[i];
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
    return 1;
  }

  u8 best_buf[16];
  int best_size = -1;
  for (int i = 0; i < matched_encodings; i++) {
    EncodingResult result = encode(ins, encodings[i]);
    u8 buf[16];
    int size = print_encoding(&result, buf);
    print_bytes(buf, size);
//    if (best_size == -1 || size < best_size) {
//      best_size = size;
//      for (int i = 0; i < size; i++) {
//        best_buf[i] = buf[i];
//      }
//    }
  }
//  print_bytes(best_buf, best_size);

  return 0;
}

__attribute__((force_align_arg_pointer))
void
_start(void) {
  int argc;
  const char **argv;
  asm volatile("movl 8(%%rbp), %0;"
               "lea 16(%%rbp), %1;"
               : "=r"(argc), "=r"(argv));

  exit(main(argc, argv));
}

int strncmp(const char *s1, const char *s2, int n) {
  while (n && (*s1 == *s2)) {
    s1++;
    s2++;
    n--;
  }
  if (n == 0) return 0;
  return *s1 - *s2;
}

int strcmp(const char *a, const char *b) {
  const unsigned char *s1 = (const unsigned char*)a;
  const unsigned char *s2 = (const unsigned char*)b;
  unsigned char c1, c2;
  do {
    c1 = *s1++;
    c2 = *s2++;
    if (c1 == '\0') return c1 - c2;
  } while (c1 == c2);
  return c1 - c2;
}

void *bsearch(const void *key, const void *base0, u64 nmemb, u64 size,
              int (*compar)(const void *, const void *)) {
  const char *base = (const char *)base0;
  int lim, cmp;
  const void *p;
  for (lim = nmemb; lim != 0; lim >>= 1) {
    p = base + (lim >> 1) * size;
    cmp = compar(key, p);
    if (cmp == 0) return (void*)p;
    if (cmp > 0) {
      base = (const char *)p + size;
      lim--;
    }
  }
  return 0;
}

#define SYS_READ  0x00
#define SYS_WRITE 0x01
#define SYS_OPEN  0x02
#define SYS_CLOSE 0x03
#define SYS_BRK   0x0c
#define SYS_EXIT  0x3c

#define STDIN 0x00

void *brk(void *ptr) {
  void *result;
  asm volatile (
    "syscall"
    : "=a"(result)
    : "a"(SYS_BRK), "D"(ptr)
    : "memory"
  );
  return result;
}

u64 read(int fd, void *buf, u64 len) {
  u64 result;
  asm volatile (
    "syscall"
    : "=a"(result)
    : "a"(SYS_READ), "D"(fd), "S"(buf), "d"(len)
    : "memory"
  );
  return result;
}

int open(const char *filename, FileFlags flags, FileMode mode) {
  u64 result;
  asm volatile (
    "syscall"
    : "=a"(result)
    : "a"(SYS_OPEN), "D"(filename), "S"(flags), "d"(mode)
  );
  return result;
}

int close(int fd) {
  u64 result;
  asm volatile (
      "syscall"
      : "=a"(result)
      : "a"(SYS_CLOSE), "D"(fd)
  );
  return result;
}



void exit(int code) {
  asm volatile (
    "syscall"
    :
    : "a"(SYS_EXIT), "D"(code)
  );
  __builtin_unreachable();
}
