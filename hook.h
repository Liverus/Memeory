#pragma once

#ifndef HOOK_H
#define HOOK_H

#include "memeory.h"

#if defined(_M_X64) || defined(__x86_64__)
	#include "hde64.h"
	typedef hde64s HDE;
	#define HDE_DISASM(code, hs) hde64_disasm(code, hs)
#else
	#include "hde32.h"
	typedef hde32s HDE;
	#define HDE_DISASM(code, hs) hde32_disasm(code, hs)
#endif


struct code_t {
	code_t() {};
	code_t(byte_t* bytes_, int size_) {
		bytes = bytes_;
		size = size_;
	};

	void free() { // i hope this is enough no fix the slight memory leak?
		delete[] bytes;
	}

	byte_t* bytes;
	int size;
};

// someday i'll figure out how to make virtual methods, inherit funcs and stuff because right now it's fucking ugly

struct op {
	code_t to_code() {
		return code_t((byte_t*)this, sizeof(this));
	}
};

struct x32_jump{
	x32_jump() {};
	x32_jump(Memory mem, ptr_t src, ptr_t addr){
		init(mem, src, addr);
	};

	void init(Memory mem, ptr_t src, ptr_t addr) {
		int delta = addr - src - sizeof(x32_jump);
		mem.write(address, &delta, sizeof(address));
	}

	code_t to_code() {
		return code_t((byte_t*)this, sizeof(this));
	}

	byte_t opcode = 0xE9;
	byte_t address[4];
};

struct x64_jump : op{
	x64_jump() {};
	x64_jump(Memory mem, ptr_t src, ptr_t addr) {
		init(mem, src, addr);
	};

	void init(Memory mem, ptr_t src, ptr_t addr) {
		mem.write(address, &addr, sizeof(address));
	}

	byte_t opcode[6] = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00 };
	byte_t address[8];
};

struct x32_call : op {
	x32_call() {};
	x32_call(Memory mem, ptr_t src, ptr_t addr) {
		init(mem, src, addr);
	};

	void init(Memory mem, ptr_t src, ptr_t addr) {
		int delta = addr - src - sizeof(x32_call);
		mem.write(address, &delta, sizeof(address));
	}

	byte_t opcode = 0xE8;
	byte_t address[4];
};

struct x64_call : op {
	x64_call() {};
	x64_call(Memory mem, ptr_t src, ptr_t addr) {
		init(mem, src, addr);
	};

	void init(Memory mem, ptr_t src, ptr_t addr) {
		mem.write(address, &addr, sizeof(address));
	}

	byte_t opcode[8] = { 0xFF, 0x15, 0x02, 0x00, 0x00, 0x00, 0xEB, 0x08 };
	byte_t address[8];
};

#if defined(_M_X64) || defined(__x86_64__)
	typedef x64_jump Jump;
	typedef x64_call Call;
#else
	typedef x32_jump Jump;
	typedef x32_call Call;
#endif

struct x64_je : op {
	x64_je() {};
	x64_je(Memory mem, ptr_t src, ptr_t addr) {
		inilialize(mem, src, addr);
	};

	void inilialize(Memory mem, ptr_t src, ptr_t addr) {
		jmp = Jump(mem, src, addr);
		byte_t sz = sizeof(jmp);
		mem.write(&offset, &sz, sizeof(offset));
	}

	byte_t opcode = 0x75; //74 = Je | 75 = Jne (Inverted)
	byte_t offset;
	Jump   jmp;
};

struct x64_jne : op {
	x64_jne() {};
	x64_jne(Memory mem, ptr_t src, ptr_t addr) {
		inilialize(mem, src, addr);
	};

	void inilialize(Memory mem, ptr_t src, ptr_t addr) {
		jmp = Jump(mem, src, addr);
		byte_t sz = sizeof(jmp);
		mem.write(&offset, &sz, sizeof(offset));
	}

	byte_t opcode = 0x74; //74 = Je | 75 = Jne (Inverted)
	byte_t offset;
	Jump   jmp;
};

typedef x64_je Je;
typedef x64_jne Jne;

struct Hook {
	Hook();
	Hook(Memory memory, void* target_addr, void* src_addr);
	Hook(Memory memory, const char* moduleName, const char* exportName, void* src_addr);

	// FUCK YOU I HATE CPP
	//template<typename Function>
	//Function  get_original();

	void*  get_original();
	void*  load();
	void   unload();
	code_t absolutify(code_t stolen_code, ptr_t gateway);
	void   inilialize(Memory mem, void* addr, void* new_addr);
	int    get_code_size(ptr_t addr, int min_len);

	Memory memory;
	bool   loaded;
	void*  target_address;
	void*  src_address;
	void*  gateway;
	int    size;
	Jump   jump_forward;
	Jump   jump_backward;

	bool success();
	bool initialized = false;
};

#endif