#ifndef HOOK_H
#define HOOK_H

#include "memeory.hpp"

#if defined(_M_X64) || defined(__x86_64__)
	#include "./hde/hde64.h"
	typedef hde64s HDE;
	#define HDE_DISASM(code, hs) hde64_disasm(code, hs)
#else
	#include "hde/hde32.h"
	typedef hde32s HDE;
	#define HDE_DISASM(code, hs) hde32_disasm(code, hs)
#endif

struct code_t {
	code_t() {};
	code_t(byte_t* abs, int newsize) {
		bytes = abs;
		size = newsize;
	};

	void Free() {
		delete[size] bytes;
	};

	byte_t* bytes;
	int   size;
};

struct x32_jump {
	x32_jump() {};
	x32_jump(Memory mem, ptr_t src, ptr_t addr) {
		init(mem, src, addr);
	};
	x32_jump(ptr_t src, ptr_t addr) {
		Memory mem;
		init(mem, src, addr);
	};

	void init(Memory mem, ptr_t src, ptr_t addr) {
		int delta = addr - src - sizeof(x32_jump);
		mem.write(address, &delta, sizeof(address));
	}

	byte_t opcode = 0xE9;
	byte_t address[4];
};

struct x64_jump {
	x64_jump() {};
	x64_jump(Memory mem, ptr_t src, ptr_t addr) {
		init(mem, src, addr);
	};
	x64_jump(ptr_t src, ptr_t addr) {
		Memory mem;
		init(mem, src, addr);
	};

	void init(Memory mem, ptr_t src, ptr_t addr) {
		mem.write(address, &addr, sizeof(address));
	}

	byte_t opcode[6] = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00 };
	byte_t address[8];
};

struct x32_call {
	x32_call() {};
	x32_call(Memory mem, ptr_t src, ptr_t addr) {
		init(mem, src, addr);
	};
	x32_call(ptr_t src, ptr_t addr) {
		Memory mem;
		init(mem, src, addr);
	};

	void init(Memory mem, ptr_t src, ptr_t addr) {
		int delta = addr - src - sizeof(x32_call);
		mem.write(address, &delta, sizeof(address));
	}

	byte_t opcode = 0xE8;
	byte_t address[4];
};

struct x64_call {
	x64_call() {};
	x64_call(Memory mem, ptr_t src, ptr_t addr) {
		init(mem, src, addr);
	};
	x64_call(ptr_t src, ptr_t addr) {
		Memory mem;
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

struct x64_je {
	x64_je() {};
	x64_je(Memory mem, ptr_t src, ptr_t addr) {
		init(mem, src, addr);
	};
	x64_je(ptr_t src, ptr_t addr) {
		Memory mem;
		init(mem, src, addr);
	};

	void init(Memory mem, ptr_t src, ptr_t addr) {
		jmp = Jump(mem, src, addr);
		byte_t sz = sizeof(jmp);
		mem.write(&offset, &sz, sizeof(offset));
	}

	byte_t opcode = 0x75; //74 = Je | 75 = Jne (Inverted)
	byte_t offset;
	Jump   jmp;
};

struct x64_jne {
	x64_jne() {};
	x64_jne(Memory mem, ptr_t src, ptr_t addr) {
		init(mem, src, addr);
	};
	x64_jne(ptr_t src, ptr_t addr) {
		Memory mem;
		init(mem, src, addr);
	};

	void init(Memory mem, ptr_t src, ptr_t addr) {
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

struct Hook
{
public:
	bool   loaded;

	void*  target_address;
	void*  src_address;
	void*  gateway;

	int    size;

	Jump   jump_forward;
	Jump   jump_backward;

	Memory memory;

	Hook() {};
	Hook(Memory memory, void* target_addr, void* src_addr) {
		setup(memory, target_addr, src_addr);
	};
	Hook(Memory memory, const char* moduleName, const char* exportName, void* src_addr) {
		setup(memory, memory.findfunction(moduleName, exportName), src_addr);
	};

	void* load() {

		// write jump from src to gateway
		memory.write(src_address, &jump_forward, sizeof(jump_forward));

		// nop remaining bytes after src jump
		memory.nop((void*)((ptr_t)src_address + sizeof(jump_forward)), size - sizeof(jump_forward));

		loaded = true;

		return gateway;
	};

	void unload() {
		// re-write stolen bytes to src
		memory.write(src_address, gateway, size);
		loaded = false;
	};

	code_t absolutify(code_t stolen_code, ptr_t gateway) {
		int     size = stolen_code.size;
		byte_t* code = stolen_code.bytes;

		HDE hs;
		int new_size = 0;
		int offset = 0;

		byte_t* temp_code = new byte_t[size * 4]; // 16/5 < 4 | size*4 = maximum new_size

		while (offset < size) {
			ptr_t actual_ptr = ((ptr_t)code + offset);
			int instruction_size = HDE_DISASM((void*)actual_ptr, &hs);
			if (hs.flags & F_ERROR) {
				break;
			}
			else {
				switch(hs.opcode) {
					case 0xE8: // rel call
						ptr_t call_addr = (actual_ptr + hs.len + hs.imm.imm32);
						Call new_call = Call(gateway, call_addr);

						memcpy(temp_code + new_size, &new_call, sizeof(new_call));

						new_size += sizeof(new_call);
					case 0xE9:  // rel jump
						ptr_t jump_addr = (actual_ptr + hs.len + hs.imm.imm32);
						Jump new_jump = Jump(gateway, jump_addr);

						memcpy(temp_code + new_size, &new_jump, sizeof(new_jump));

						new_size += sizeof(new_jump);
				
					case 0x75: // rel conditionnal jump
						ptr_t jne_addr = (actual_ptr + hs.len + hs.imm.imm32);
						Jne new_jne = Jne(gateway, jne_addr);

						memcpy(temp_code + new_size, &new_jne, sizeof(new_jne));

						new_size += sizeof(new_jne);
					case 0x74: // rel conditionnal jump
						ptr_t je_addr = (actual_ptr + hs.len + hs.imm.imm32);
						Je new_je = Je(gateway, je_addr);

						memcpy(temp_code + new_size, &new_je, sizeof(new_je));

						new_size += sizeof(new_je);
					default:
						memcpy(temp_code + new_size, (void*)actual_ptr, instruction_size);
						new_size += instruction_size;
				};

				offset += instruction_size;
			}
		}

		byte_t* new_code = new byte_t[new_size];
		memcpy(new_code, temp_code, new_size);

		delete[] temp_code;

		return code_t(new_code, new_size);
	};

	void setup(Memory mem, void* addr, void* new_addr) {

		memory = mem;
		//size           = size;
		src_address = addr;
		target_address = new_addr;

		// Setup  Jumps
		jump_forward = Jump(memory, (ptr_t)src_address, (ptr_t)target_address);
		size = get_code_size((ptr_t)src_address, sizeof(jump_forward));

		byte_t* code_cache = new byte_t[size];
		memory.write(code_cache, addr, size);


		gateway = VirtualAlloc(0, (size * 4) + sizeof(Jump), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		code_t new_func = absolutify(code_t((byte_t*)addr, size), (ptr_t)gateway);

		if (size < sizeof(jump_forward)) {
			return;
		}

		jump_backward = Jump(memory, (ptr_t)gateway + new_func.size, (ptr_t)src_address + size);

		// write stolen bytes
		memory.write(gateway, new_func.bytes, new_func.size);

		// write jump from gateway to src
		memory.write((void*)((ptr_t)gateway + new_func.size), &jump_backward, sizeof(jump_backward));
	};

	int get_code_size(ptr_t addr, int min_len) {
		HDE hs;
		int offset = 0;

		while (offset < min_len) {
			int instruction_size = HDE_DISASM((void*)((ptr_t)addr + offset), &hs);
			if (hs.flags & F_ERROR) {
				break;
			}
			else {
				offset += instruction_size;
			}
		}

		return offset;
	};
};
#endif