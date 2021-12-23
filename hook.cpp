#include "hook.h"
#include <iostream>

Hook::Hook() {};

Hook::Hook(Memory memory_, void* target_addr_, void* src_addr_) {
	memory = memory_;
	src_address = target_addr_;
	target_address = src_addr_;

	initialize();
};

Hook::Hook(Memory memory_, const char* moduleName, const char* exportName, void* src_addr_) {
	memory = memory_;
	src_address = memory.find_function<void*>(moduleName, exportName);
	target_address = src_addr_;

	initialize();
};

bool Hook::success() {
	return initialized;
}

void Hook::load() {

	// write jump from src to gateway
	memory.write(src_address, &jump_forward, sizeof(jump_forward));

	// nop remaining bytes after src jump
	memory.nop((void*)((ptr_t)src_address + sizeof(jump_forward)), size - sizeof(jump_forward));

	loaded = true;
};

void Hook::unload() {
	// re-write stolen bytes to src
	memory.write(src_address, gateway, size);

	loaded = false;
};

code_t Hook::absolutify(code_t stolen_code, ptr_t gateway) {
	int     size = stolen_code.size;
	byte_t* code = stolen_code.bytes;

	HDE hs;
	int new_size = 0;
	int offset = 0;

	byte_t* temp_code = new byte_t[size * 4]; // 16/5 < 4 | size * 4 = maximum new_size

	while (offset < size) {
		ptr_t actual_ptr = ((ptr_t)code + offset);
		int instruction_size = HDE_DISASM((void*)actual_ptr, &hs);

		if (hs.flags & F_ERROR) {
			break;
		}
		else {
			ptr_t actual_new_dimm = (actual_ptr + hs.len + hs.imm.imm32);
			ptr_t actual_new_disp = (actual_ptr + hs.len + hs.disp.disp32);

			code_t actual_new_code;
			
			switch (hs.opcode) { 
				case 0xE8: // rel call
					actual_new_code = CALL(memory, gateway, actual_new_dimm).to_code(sizeof(CALL));
					break;

				case 0xE9: // rel jump
					actual_new_code = JUMP(memory, gateway, actual_new_dimm).to_code(sizeof(JUMP));
					break;
	
				case 0x75: // rel conditionnal jump
					actual_new_code = JNE(memory, gateway, actual_new_dimm).to_code(sizeof(JNE));
					break;

				case 0x74: // rel conditionnal jump
					actual_new_code = JE(memory, gateway, actual_new_dimm).to_code(sizeof(JE));
					break;

				case 0x83: // sub, cmp, ?
					if (hs.modrm == 0x3D) { // cmp
						actual_new_code = CMP(memory, gateway, actual_new_disp).to_code(sizeof(CMP));
						break;
					}

				default: // just copy the actual instruction, no need to absolutify
					actual_new_code = code_t((byte_t*)actual_ptr, instruction_size);
			}

			memcpy(temp_code + new_size, actual_new_code.bytes, actual_new_code.size);
			new_size += actual_new_code.size;

			offset += instruction_size;
		}
	}

	byte_t* new_code = new byte_t[new_size];
	memcpy(new_code, temp_code, new_size);

	delete[] temp_code;

	return code_t(new_code, new_size);
};

void Hook::initialize() {

	// Setup  Jumps
	jump_forward = JUMP(memory, (ptr_t)src_address, (ptr_t)target_address);
	size = get_code_size((ptr_t)src_address, sizeof(jump_forward));

	byte_t* code_cache = new byte_t[size];
	memory.write(code_cache, target_address, size);


	gateway = VirtualAlloc(0, (size * 4) + sizeof(JUMP), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	code_t new_func = absolutify(code_t((byte_t*)src_address, size), (ptr_t)gateway);

	if (size < sizeof(jump_forward)) {
		return;
	}

	jump_backward = JUMP(memory, (ptr_t)gateway + new_func.size, (ptr_t)src_address + size);

	// write stolen bytes
	memory.write(gateway, new_func.bytes, new_func.size);

	// write jump from gateway to src
	memory.write((void*)((ptr_t)gateway + new_func.size), &jump_backward, sizeof(jump_backward));

	new_func.free();

	initialized = true;
};

int Hook::get_code_size(ptr_t addr, int min_len) {
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