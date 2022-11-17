#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

typedef enum {
  AL = 1,
  AX,
  EAX,
  RAX,

  CL,
  CX,
  ECX,
  RCX,

  DL,
  DX,
  EDX,
  RDX,

  BL,
  BX,
  EBX,
  RBX,

  SIL,
  SI,
  ESI,
  RSI,

  DIL,
  DI,
  EDI,
  RDI,

  SPL,
  SP,
  ESP,
  RSP,

  BPL,
  BP,
  EBP,
  RBP,

  R8B,
  R8W,
  R8D,
  R8,

  R9B,
  R9W,
  R9D,
  R9,

  R10B,
  R10W,
  R10D,
  R10,

  R11B,
  R11W,
  R11D,
  R11,

  R12B,
  R12W,
  R12D,
  R12,

  R13B,
  R13W,
  R13D,
  R13,

  R14B,
  R14W,
  R14D,
  R14,

  R15B,
  R15W,
  R15D,
  R15,

  AH,
  CH,
  DH,
  BH,
} Register;

typedef enum {
  REX   = 0b01000000,
  REX_W = 0b01001000,
  REX_R = 0b01000100,
  REX_X = 0b01000010,
  REX_B = 0b01000001,
} REX_BYTE;

typedef struct {
  u8 mod : 2;
  u8 reg : 3;
  u8 r_m : 3;
} MOD_RM;

typedef enum {
  OPERAND_TYPE_REGISTER,
} Operand_Type;

typedef struct {
  Register name;
} Operand_Register;

typedef struct {
  Operand_Type type;
  union {
    Operand_Register reg;
  };
} Operand;

typedef enum {
  MOV,
} Mnemonic;

typedef struct {
  Mnemonic mnemonic;
  Operand operands[2];
} Instruction;

typedef struct {

} OperandEncoding;

typedef struct {

} InstructionExtensionType;

typedef struct {
  u8 op_code[4];
  InstructionExtensionType extension_type;
  u8 op_code_extension;
  u8 op_code_extension_padding[3];
  OperandEncoding operands[3];
} InstructionEncoding;

typedef struct {
  const char *name;
  const InstructionEncoding *encodings;
  u64 encoding_count;
} Mnemonic;


int
encode_mov(Operand op1, Operand op2) {
}

typedef struct {
  const char *mnemonic;
  u8 encoding_count;
  Instruction_Encoding encodings[];
} Opcode_Definition;

Opcode_Definition opcodes[] = {
    { .mnemonic = "mov", .encoding_count = 2, .encodings = {

    }},
};

int main() {
  char *line = NULL;
  size_t len = 0;
  ssize_t nread;

  while ((nread = getline(&line, &len, stdin)) != -1) {
    printf("%zd >>> %s", nread, line);
  }

  free(line);
  return 0;
}
