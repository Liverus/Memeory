#include "hook.h"

namespace Memory{
	Hook::Hook() {};

	Hook::Hook(void* src_addr, void* target_addr, void* original_address) {
		Initialize(src_addr, target_addr, original_address);
	};

	Hook::Hook(void* src_addr, int index, void* target_addr, void* original_address) {
		Initialize(Memory::VMT_Method<void*>(src_addr, index), target_addr, original_address);
	};

	Hook::Hook(const char* module_name, const char* export_name, void* target_addr, void* original_address) {
		Initialize(Memory::FindFunction<void*>(module_name, export_name), target_addr, original_address);
	};

	void Hook::Initialize(void* src_addr_, void* target_addr_, void* original_address_) {

		src_address = src_addr_;
		target_address = target_addr_;
		original_address = original_address_;

		list.push_back(*this);

		SetupJumps();
		Load();
	}

	void Hook::SetupJumps() {

		// Jump: orignal -> hook
		jump_forward = jump_t(src_address, target_address);

		// Check payload length
		minimum_size = Memory::GetMinimumCodeSize(src_address, sizeof(jump_t));

		if (minimum_size == -1) {
			Memory::Error(MEMEORY_CODE::HOOK_MISSING_SPACE);
			return;
		}

		func_size = Memory::GetCodeSize(src_address);

		// Dynamically allocate memory for our gateway
		void* gateway_ptr = VirtualAlloc(0, (minimum_size * 4) + sizeof(jump_t), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		void* original_code_ptr = VirtualAlloc(0, minimum_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

		if (!gateway_ptr || !original_code_ptr) {
			Memory::Error(MEMEORY_CODE::ALLOCATION_FAILED);
			return;
		}

		// Absolutify the original code so it works when delocalized
		code_t new_func = Memory::Absolutify(code_t((byte_t*)src_address, minimum_size), gateway_ptr);

		// Copy the absolutified code to the gateway
		Memory::Write(gateway_ptr, new_func.bytes, new_func.size);
		Memory::Write(original_code_ptr, src_address, new_func.size);

		gateway = gateway_ptr;
		original_code = code_t((byte_t*)original_code_ptr, minimum_size);

		// If there is no code left, no need for backward jump (Ex: src is only a jmp)
		if (func_size - minimum_size > 0) {

			// Jump: gateway's end -> original function + jmp instruction
			jump_backward = jump_t((void*)((ptr_t)gateway + new_func.size), (void*)((ptr_t)src_address + minimum_size));

			// Copy our jump at the end of the gateway
			Memory::Write((void*)((ptr_t)gateway + new_func.size), &jump_backward, sizeof(jump_t));
		}

		// Sets our original to the entry of our gateway
		if (original_address) {
			*(void**)original_address = gateway;
		}

		new_func.free();
	};

	void Hook::Load() {

		// Jump: original -> hook
		Memory::Write(src_address, &jump_forward, sizeof(jump_t));

		int nop_size = minimum_size - sizeof(jump_t);

		// Nop remaining bits
		if (nop_size > 0) {
			Memory::Nop((void*)((ptr_t)src_address + sizeof(jump_t)), nop_size);
		}

		loaded = true;
	};

	void Hook::Unload() {

		// Replace jump with original code
		Memory::Write(src_address, original_code.bytes, original_code.size);

		loaded = false;
	};

	void Hook::UnloadAll() {
		for (Hook hk : list) {
			hk.Unload();
		}
	}

	std::vector<Hook> Hook::list;
}