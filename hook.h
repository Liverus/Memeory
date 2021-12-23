#pragma once

#ifndef HOOK_H
#define HOOK_H

#include "memeory.h"

#if defined(_M_X64) || defined(__x86_64__)
	#include "hde64.h"
	typedef hde64s HDE;
	#define HDE_DISASM(code, hs) hde64_disasm(code, hs)
	#define MEMEORY_X64
#else
	#include "hde32.h"
	typedef hde32s HDE;
	#define HDE_DISASM(code, hs) hde32_disasm(code, hs)
	#define MEMEORY_X32
#endif


struct code_t {
	code_t() {};
	code_t(byte_t* bytes_, int size_) {
		bytes = bytes_;
		size = size_;
	};

	void free() { // i don't know what i'm doing pls help
		delete[] bytes;
	}

	byte_t* bytes;
	int size;
};

// someday i'll figure out how to make virtual methods, inherit funcs and stuff because right now it's fucking ugly

struct op {
	code_t to_code(size_t size) {
		return code_t((byte_t*)this, size);
	}
};

struct x32_jump : op{
	x32_jump() {};
	x32_jump(Memory mem, ptr_t src, ptr_t addr){
		int delta = addr - src - sizeof(x32_jump);

		mem.write(address, &delta, sizeof(address));
	};

	byte_t opcode = 0xE9;
	byte_t address[4];
};

struct x64_jump : op{
	x64_jump() {};
	x64_jump(Memory mem, ptr_t src, ptr_t addr) {
		mem.write(address, &addr, sizeof(address));
	};

	byte_t opcode[6] = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00 };
	byte_t address[8];
};

struct x32_call : op {
	x32_call() {};
	x32_call(Memory mem, ptr_t src, ptr_t addr) {
		int delta = addr - src - sizeof(x32_call);

		mem.write(address, &delta, sizeof(address));
	};

	byte_t opcode = 0xE8;
	byte_t address[4];
};

struct x64_call : op {
	x64_call() {};
	x64_call(Memory mem, ptr_t src, ptr_t addr) {
		mem.write(address, &addr, sizeof(address));
	};

	byte_t opcode[8] = { 0xFF, 0x15, 0x02, 0x00, 0x00, 0x00, 0xEB, 0x08 };
	byte_t address[8];
};


struct x32_mov : op {
	x32_mov() {};
	x32_mov(Memory mem, ptr_t src, ptr_t addr) {
		mem.write(address, &addr, sizeof(address));
	};

	byte_t opcode[2] = { 0x48, 0xB8 };
	byte_t address[4];
};

struct x64_mov : op {
	x64_mov() {};
	x64_mov(Memory mem, ptr_t src, ptr_t addr) {
		mem.write(address, &addr, sizeof(address));
	};

	byte_t opcode[2] = { 0x48, 0xB8 };
	byte_t address[8];
};

#if defined(_M_X64) || defined(__x86_64__)
	typedef x64_jump JUMP;
	typedef x64_call CALL;
	typedef x64_mov MOV;
#else
	typedef x32_jump JUMP;
	typedef x32_call CALL;
	typedef x32_mov MOV;
#endif

struct x64_je : op {
	x64_je() {};
	x64_je(Memory mem, ptr_t src, ptr_t addr) {
		jmp = JUMP(mem, src, addr);
		byte_t sz = sizeof(jmp);

		mem.write(&offset, &sz, sizeof(offset));
	};

	byte_t opcode = 0x75; //74 = Je | 75 = Jne (Inverted)
	byte_t offset;
	JUMP   jmp;
};

struct x64_jne : op {
	x64_jne() {};
	x64_jne(Memory mem, ptr_t src, ptr_t addr) {
		jmp = JUMP(mem, src, addr);
		byte_t sz = sizeof(jmp);

		mem.write(&offset, &sz, sizeof(offset));
	};

	byte_t opcode = 0x74; //74 = Je | 75 = Jne (Inverted)
	byte_t offset;
	JUMP   jmp;
};

typedef x64_je JE;
typedef x64_jne JNE;

struct x64_cmp : op {
	x64_cmp() {};
	x64_cmp(Memory mem, ptr_t src, ptr_t addr) {
		mov = MOV(mem, src, addr);
	};

	byte_t push_eax = 0x50; 
	MOV mov; 
	byte_t test_eax[3] = { 0x48, 0x85, 0xC0 }; 
	byte_t pop_eax = 0x58; 

	// Before:
		// cmp qword ptr [annoying_relative_address], imm

	// After:
		// push eax
		// mov eax, good_absolute_address :D
		// test eax, eax
		// pop eax
};

typedef x64_cmp CMP;

struct Hook {
	Hook();
	Hook(Memory memory, void* target_addr, void* src_addr);
	Hook(Memory memory, const char* moduleName, const char* exportName, void* src_addr);

	template<typename T>
	T get_original()
	{
		if (loaded) {
			return (T)gateway;
		}

		return 0;
	}

	void*  get_original();
	void   load();
	void   unload();
	code_t absolutify(code_t stolen_code, ptr_t gateway);
	void   initialize();
	int    get_code_size(ptr_t addr, int min_len);

	Memory memory;
	bool   loaded;
	void*  target_address;
	void*  src_address;
	void*  gateway;
	int    size;
	JUMP   jump_forward;
	JUMP   jump_backward;

	bool success();
	bool initialized = false;
};

#endif