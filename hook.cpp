#include "hook.h"

Hook::Hook() {};

Hook::Hook(Memory memory, void* target_addr, void* src_addr) {
	inilialize(memory, target_addr, src_addr);
};

Hook::Hook(Memory memory, const char* moduleName, const char* exportName, void* src_addr) {
	inilialize(memory, memory.find_function(moduleName, exportName), src_addr);
};

bool Hook::success() {
	return initialized;
}

// FUCK YOU I HATE CPP
//template<typename Function>
//Function Hook::get_original()
//{
//	if (loaded) {
//		return gateway;
//	}
//}

void* Hook::get_original()
{
	if (loaded) {
		return gateway;
	} else {
		return src_address;
	}
}

void* Hook::load() {

	// write jump from src to gateway
	memory.write(src_address, &jump_forward, sizeof(jump_forward));

	// nop remaining bytes after src jump
	memory.nop((void*)((ptr_t)src_address + sizeof(jump_forward)), size - sizeof(jump_forward));

	loaded = true;

	return gateway;
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

	byte_t* temp_code = new byte_t[size * 4]; // 16/5 < 4 | size*4 = maximum new_size

	while (offset < size) {
		ptr_t actual_ptr = ((ptr_t)code + offset);
		int instruction_size = HDE_DISASM((void*)actual_ptr, &hs);

		if (hs.flags & F_ERROR) {
			break;
		}
		else {
			ptr_t actual_new_ptr = (actual_ptr + hs.len + hs.imm.imm32);
			code_t actual_new_code;

			switch (hs.opcode) { 
				case 0xE8: // rel call
					actual_new_code = Call(memory, gateway, actual_new_ptr).to_code();

				case 0xE9: // rel jump
					actual_new_code = Jump(memory, gateway, actual_new_ptr).to_code();
	
				case 0x75: // rel conditionnal jump
					actual_new_code = Jne(memory, gateway, actual_new_ptr).to_code();

				case 0x74: // rel conditionnal jump
					actual_new_code = Je(memory, gateway, actual_new_ptr).to_code();

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

void Hook::inilialize(Memory mem, void* addr, void* new_addr) {

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