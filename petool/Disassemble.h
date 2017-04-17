#pragma once

#include <windows.h>

#include <distorm.h>
#include <functional>

#include "Rva.h"

typedef std::function<bool(const _CodeInfo &ci, Rva va, const _DInst &dinst)> InstructionHandler;

extern void Disassemble(const unsigned char *buf, Rva va, DWORD size, InstructionHandler handler);


