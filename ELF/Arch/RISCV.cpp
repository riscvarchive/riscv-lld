//===- RISCV.cpp ----------------------------------------------------------===//
//
//                             The LLVM Linker
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "Bits.h"
#include "InputFiles.h"
#include "Symbols.h"
#include "SyntheticSections.h"
#include "Target.h"

using namespace llvm;
using namespace llvm::object;
using namespace llvm::support::endian;
using namespace llvm::ELF;
using namespace lld;
using namespace lld::elf;

namespace {

class RISCV final : public TargetInfo {
public:
  RISCV();
  virtual uint32_t calcEFlags() const override;
  RelExpr getRelExpr(RelType Type, const Symbol &S,
                     const uint8_t *Loc) const override;
  void relocateOne(uint8_t *Loc, RelType Type, uint64_t Val) const override;

  virtual void writeGotPltHeader(uint8_t *Buf) const override;
  virtual void writeGotHeader(uint8_t *Buf) const override;
  virtual void writeGotPlt(uint8_t *Buf, const Symbol &S) const override;

  virtual void writePltHeader(uint8_t *Buf) const override;

  virtual void writePlt(uint8_t *Buf, uint64_t GotEntryAddr,
                        uint64_t PltEntryAddr, int32_t Index,
                        unsigned RelOff) const override;

  virtual bool usesOnlyLowPageBits(RelType Type) const override;
};

} // end anonymous namespace

RISCV::RISCV() {
  CopyRel = R_RISCV_COPY;
  RelativeRel = R_RISCV_RELATIVE;
  GotRel = Config->Is64 ? R_RISCV_64 : R_RISCV_32;
  PltRel = R_RISCV_JUMP_SLOT;
  GotEntrySize = Config->Wordsize;
  GotPltEntrySize = Config->Wordsize;
  PltEntrySize = 16;
  PltHeaderSize = 32;
  GotHeaderEntriesNum = 1;
  GotPltHeaderEntriesNum = 2;
  GotBaseSymInGotPlt = false;
}

static uint32_t getEFlags(InputFile *F) {
  if (Config->Is64)
    return cast<ObjFile<ELF64LE>>(F)->getObj().getHeader()->e_flags;
  else
    return cast<ObjFile<ELF32LE>>(F)->getObj().getHeader()->e_flags;
}

uint32_t RISCV::calcEFlags() const {
  assert(!ObjectFiles.empty());

  uint32_t Target = getEFlags(ObjectFiles.front());

  for (InputFile *F : ObjectFiles) {
    uint32_t EFlags = getEFlags(F);
    if (EFlags & EF_RISCV_RVC)
      Target |= EF_RISCV_RVC;

    if ((EFlags & EF_RISCV_FLOAT_ABI) != (Target & EF_RISCV_FLOAT_ABI))
      error(toString(F) +
            ": cannot link object files with different floating-point ABI");

    if ((EFlags & EF_RISCV_RVE) != (Target & EF_RISCV_RVE))
      error(toString(F) +
            ": cannot link object files with different EF_RISCV_RVE");
  }

  return Target;
}

bool RISCV::usesOnlyLowPageBits(RelType Type) const {
  return Type == R_RISCV_LO12_I || Type == R_RISCV_PCREL_LO12_I ||
         Type == R_RISCV_LO12_S || Type == R_RISCV_PCREL_LO12_S ||
         // These are used in a pair to calculate relative address in debug
         // sections, so they aren't really absolute. We list those here as a
         // hack so the linker doesn't try to create dynamic relocations.
         Type == R_RISCV_ADD8 || Type == R_RISCV_ADD16 ||
         Type == R_RISCV_ADD32 || Type == R_RISCV_ADD64 ||
         Type == R_RISCV_SUB8 || Type == R_RISCV_SUB16 ||
         Type == R_RISCV_SUB32 || Type == R_RISCV_SUB64 ||
         Type == R_RISCV_SUB6 ||
         Type == R_RISCV_SET6 || Type == R_RISCV_SET8 ||
         Type == R_RISCV_SET16 || Type == R_RISCV_SET32;
}

void RISCV::writeGotPltHeader(uint8_t *Buf) const {
  writeUint(Buf, -1);                  // __dl_runtime_resolve
  writeUint(Buf + GotPltEntrySize, 0); // link_map
}

void RISCV::writeGotHeader(uint8_t *Buf) const {
  // _GLOBAL_OFFSET_TABLE_ points to the start of .got section which contains
  // the address of .dynamic section.
  if (ElfSym::GlobalOffsetTable)
    writeUint(Buf, InX::Dynamic->getVA());
}

void RISCV::writeGotPlt(uint8_t *Buf, const Symbol &S) const {
  writeUint(Buf, InX::Plt->getVA());
}

void RISCV::writePltHeader(uint8_t *Buf) const {
  uint64_t PcRelGotPlt = InX::GotPlt->getVA() - InX::Plt->getVA();

  write32le(Buf + 0, 0x00000397);    // 1: auipc  t2, %pcrel_hi(.got.plt)
  relocateOne(Buf + 0, R_RISCV_PCREL_HI20, PcRelGotPlt);
  write32le(Buf + 4, 0x41c30333);    // sub    t1, t1, t3
  if (Config->Is64) {
    write32le(Buf + 8, 0x0003be03);  // ld     t3, %pcrel_lo(1b)(t2)
  } else {
    write32le(Buf + 8, 0x0003ae03);  // lw     t3, %pcrel_lo(1b)(t2)
  }
  relocateOne(Buf + 8, R_RISCV_PCREL_LO12_I, PcRelGotPlt);
  write32le(Buf + 12, 0xfd430313);   // addi   t1, t1, -44
  write32le(Buf + 16, 0x00038293);   // addi   t0, t2, %pcrel_lo(1b)
  relocateOne(Buf + 16, R_RISCV_PCREL_LO12_I, PcRelGotPlt);
  if (Config->Is64) {
    write32le(Buf + 20, 0x00135313); // srli   t1, t1, 1
    write32le(Buf + 24, 0x0082b283); // ld     t0, 8(t0)
  } else {
    write32le(Buf + 20, 0x00235313); // srli   t1, t1, 2
    write32le(Buf + 24, 0x0042a283); // lw     t0, 4(t0)
  }
  write32le(Buf + 28, 0x000e0067);   // jr     t3
}

void RISCV::writePlt(uint8_t *Buf, uint64_t GotEntryAddr, uint64_t PltEntryAddr,
                     int32_t Index, unsigned RelOff) const {
  write32le(Buf + 0, 0x00000e17);   // auipc   t3, %pcrel_hi(f@.got.plt)
  if (Config->Is64) {
    write32le(Buf + 4, 0x000e3e03); // ld      t3, %pcrel_lo(-4)(t3)
  } else {
    write32le(Buf + 4, 0x000e2e03); // lw      t3, %pcrel_lo(-4)(t3)
  }
  write32le(Buf + 8, 0x000e0367);   // jalr    t1, t3
  write32le(Buf + 12, 0x00000013);   // nop

  relocateOne(Buf + 0, R_RISCV_PCREL_HI20, GotEntryAddr - PltEntryAddr);
  relocateOne(Buf + 4, R_RISCV_PCREL_LO12_I, GotEntryAddr - PltEntryAddr);
}

RelExpr RISCV::getRelExpr(const RelType Type, const Symbol &S,
                          const uint8_t *Loc) const {
  switch (Type) {
  case R_RISCV_JAL:
  case R_RISCV_BRANCH:
  case R_RISCV_CALL:
  case R_RISCV_PCREL_HI20:
  case R_RISCV_RVC_BRANCH:
  case R_RISCV_RVC_JUMP:
  case R_RISCV_32_PCREL:
    return R_PC;
  case R_RISCV_CALL_PLT:
    return R_PLT_PC;
  case R_RISCV_PCREL_LO12_I:
  case R_RISCV_PCREL_LO12_S:
    return R_RISCV_PC_INDIRECT;
  case R_RISCV_GOT_HI20:
    return R_GOT_PC;
  case R_RISCV_ALIGN:
  case R_RISCV_RELAX:
    return R_HINT;
  default:
    return R_ABS;
  }
}

// Extract bits V[Begin:End], where range is inclusive, and Begin must be < 63.
static uint32_t extractBits(uint64_t V, uint32_t Begin, uint32_t End) {
  return (V & ((1ULL << (Begin + 1)) - 1)) >> End;
}

void RISCV::relocateOne(uint8_t *Loc, const RelType Type,
                        const uint64_t Val) const {
  switch (Type) {
  case R_RISCV_32:
    write32le(Loc, Val);
    return;
  case R_RISCV_64:
    write64le(Loc, Val);
    return;

  case R_RISCV_RVC_BRANCH: {
    checkInt(Loc, static_cast<int64_t>(Val) >> 1, 8, Type);
    checkAlignment(Loc, Val, 2, Type);
    uint16_t Insn = read16le(Loc) & 0xE383;
    uint16_t Imm8 = extractBits(Val, 8, 8) << 12;
    uint16_t Imm4_3 = extractBits(Val, 4, 3) << 10;
    uint16_t Imm7_6 = extractBits(Val, 7, 6) << 5;
    uint16_t Imm2_1 = extractBits(Val, 2, 1) << 3;
    uint16_t Imm5 = extractBits(Val, 5, 5) << 2;
    Insn |= Imm8 | Imm4_3 | Imm7_6 | Imm2_1 | Imm5;

    write16le(Loc, Insn);
    return;
  }

  case R_RISCV_RVC_JUMP: {
    checkInt(Loc, static_cast<int64_t>(Val) >> 1, 11, Type);
    checkAlignment(Loc, Val, 2, Type);
    uint16_t Insn = read16le(Loc) & 0xE003;
    uint16_t Imm11 = extractBits(Val, 11, 11) << 12;
    uint16_t Imm4 = extractBits(Val, 4, 4) << 11;
    uint16_t Imm9_8 = extractBits(Val, 9, 8) << 9;
    uint16_t Imm10 = extractBits(Val, 10, 10) << 8;
    uint16_t Imm6 = extractBits(Val, 6, 6) << 7;
    uint16_t Imm7 = extractBits(Val, 7, 7) << 6;
    uint16_t Imm3_1 = extractBits(Val, 3, 1) << 3;
    uint16_t Imm5 = extractBits(Val, 5, 5) << 2;
    Insn |= Imm11 | Imm4 | Imm9_8 | Imm10 | Imm6 | Imm7 | Imm3_1 | Imm5;

    write16le(Loc, Insn);
    return;
  }

  case R_RISCV_RVC_LUI: {
    int32_t Imm = ((Val + 0x800) >> 12);
    checkUInt(Loc, Imm, 6, Type);
    if (Imm == 0) { // `c.lui rd, 0` is illegal, convert to `c.li rd, 0`
      write16le(Loc, (read16le(Loc) & 0x0F83) | 0x4000);
    } else {
      uint16_t Imm17 = extractBits(Val + 0x800, 17, 17) << 12;
      uint16_t Imm16_12 = extractBits(Val + 0x800, 16, 12) << 2;
      write16le(Loc, (read16le(Loc) & 0xEF83) | Imm17 | Imm16_12);
    }
    return;
  }

  case R_RISCV_JAL: {
    checkInt(Loc, static_cast<int64_t>(Val) >> 1, 20, Type);
    checkAlignment(Loc, Val, 2, Type);

    uint32_t Insn = read32le(Loc) & 0xFFF;
    uint32_t Imm20 = extractBits(Val, 20, 20) << 31;
    uint32_t Imm10_1 = extractBits(Val, 10, 1) << 21;
    uint32_t Imm11 = extractBits(Val, 11, 11) << 20;
    uint32_t Imm19_12 = extractBits(Val, 19, 12) << 12;
    Insn |= Imm20 | Imm10_1 | Imm11 | Imm19_12;

    write32le(Loc, Insn);
    return;
  }

  case R_RISCV_BRANCH: {
    checkInt(Loc, static_cast<int64_t>(Val) >> 1, 12, Type);
    checkAlignment(Loc, Val, 2, Type);

    uint32_t Insn = read32le(Loc) & 0x1FFF07F;
    uint32_t Imm12 = extractBits(Val, 12, 12) << 31;
    uint32_t Imm10_5 = extractBits(Val, 10, 5) << 25;
    uint32_t Imm4_1 = extractBits(Val, 4, 1) << 8;
    uint32_t Imm11 = extractBits(Val, 11, 11) << 7;
    Insn |= Imm12 | Imm10_5 | Imm4_1 | Imm11;

    write32le(Loc, Insn);
    return;
  }

  // auipc + jalr pair
  case R_RISCV_CALL_PLT:
  case R_RISCV_CALL: {
    checkInt(Loc, Val, 32, Type);
    if (isInt<32>(Val)) {
      relocateOne(Loc, R_RISCV_PCREL_HI20, Val);
      relocateOne(Loc + 4, R_RISCV_PCREL_LO12_I, Val);
    }
    return;
  }

  case R_RISCV_PCREL_HI20:
  case R_RISCV_GOT_HI20:
  case R_RISCV_HI20: {
    checkInt(Loc, Val, 32, Type);
    uint32_t Hi = Val + 0x800;
    write32le(Loc, (read32le(Loc) & 0xFFF) | (Hi & 0xFFFFF000));
    return;
  }

  case R_RISCV_PCREL_LO12_I:
  case R_RISCV_LO12_I: {
    checkInt(Loc, Val, 32, Type);
    uint32_t Hi = Val + 0x800;
    uint32_t Lo = Val - (Hi & 0xFFFFF000);
    write32le(Loc, (read32le(Loc) & 0xFFFFF) | ((Lo & 0xFFF) << 20));
    return;
  }

  case R_RISCV_PCREL_LO12_S:
  case R_RISCV_LO12_S: {
    checkInt(Loc, Val, 32, Type);
    uint32_t Hi = Val + 0x800;
    uint32_t Lo = Val - (Hi & 0xFFFFF000);
    uint32_t Imm11_5 = extractBits(Lo, 11, 5) << 25;
    uint32_t Imm4_0 = extractBits(Lo, 4, 0) << 7;
    write32le(Loc, (read32le(Loc) & 0x1FFF07F) | Imm11_5 | Imm4_0);
    return;
  }

  case R_RISCV_ADD8:
    *Loc += Val;
    return;
  case R_RISCV_ADD16:
    write16le(Loc, read16le(Loc) + Val);
    return;
  case R_RISCV_ADD32:
    write32le(Loc, read32le(Loc) + Val);
    return;
  case R_RISCV_ADD64:
    write64le(Loc, read64le(Loc) + Val);
    return;
  case R_RISCV_SUB6:
    *Loc = (*Loc & 0xc0) | (((*Loc & 0x3f) - Val) & 0x3f);
    return;
  case R_RISCV_SUB8:
    *Loc -= Val;
    return;
  case R_RISCV_SUB16:
    write16le(Loc, read16le(Loc) - Val);
    return;
  case R_RISCV_SUB32:
    write32le(Loc, read32le(Loc) - Val);
    return;
  case R_RISCV_SUB64:
    write64le(Loc, read64le(Loc) - Val);
    return;
  case R_RISCV_SET6:
    *Loc = (*Loc & 0xc0) | (Val & 0x3f);
    return;
  case R_RISCV_SET8:
    *Loc = Val;
    return;
  case R_RISCV_SET16:
    write16le(Loc, Val);
    return;
  case R_RISCV_SET32:
  case R_RISCV_32_PCREL:
    write32le(Loc, Val);
    return;

  case R_RISCV_ALIGN:
  case R_RISCV_RELAX:
    return; // Ignored (for now)
  case R_RISCV_NONE:
    return; // Do nothing

  // These are handled by the dynamic linker
  case R_RISCV_RELATIVE:
  case R_RISCV_COPY:
  case R_RISCV_JUMP_SLOT:
  // GP-relative relocations are only produced after relaxation, which
  // we don't support for now
  case R_RISCV_GPREL_I:
  case R_RISCV_GPREL_S:
  default:
    error(getErrorLocation(Loc) +
          "unimplemented relocation: " + toString(Type));
    return;
  }
}

TargetInfo *elf::getRISCVTargetInfo() {
  static RISCV Target;
  return &Target;
}
