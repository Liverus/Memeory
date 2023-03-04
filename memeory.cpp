#include "memeory.h"

namespace Memory {

	bool initialized = false;

	const std::map<MEMEORY_CODE, const char*> MEMEORY_CODE_MESSAGE{
		{ MEMEORY_CODE::SUCCESS,                  "Success" },
		{ MEMEORY_CODE::FAIL,                     "Failed" },
		{ MEMEORY_CODE::ADMIN_PRIVILEGE_REQUIRED, "Retry with admin privileges" },
		{ MEMEORY_CODE::PROCESS_NOT_FOUND,        "Couldn't find process" },
		{ MEMEORY_CODE::WRITE_MEMORY,             "Couldn't write memory" },
		{ MEMEORY_CODE::READ_MEMORY,              "Couldn't read process" },
		{ MEMEORY_CODE::HOOK_MISSING_SPACE,       "Function too small" },
		{ MEMEORY_CODE::ALLOCATION_FAILED,        "Couldn't allocate memory" },
		{ MEMEORY_CODE::DISASSEMBLER_FAILED,      "Couldn't disassemble" }
		
	};

	MEMEORY_TYPE type;
	MEMEORY_CODE last_code;

	HANDLE handle;

	void InternalWrite(void* addr, void* buffer, size_t size) {
		if (Memory::IsExternal()) {
			if (!WriteProcessMemory(Memory::handle, addr, buffer, size, NULL)) {
				Error(MEMEORY_CODE::WRITE_MEMORY);
				return;
			}
		} else {
			memcpy(addr, buffer, size);
		}
	}

	void InternalRead(void* addr, void* buffer, size_t size) {
		if (Memory::IsExternal()) {
			if (!ReadProcessMemory(Memory::handle, addr, buffer, size, NULL)) {
				Error(MEMEORY_CODE::READ_MEMORY);
				return;
			}
		} else {
			memcpy(buffer, addr, size);
		}
	}

	void Initialize() {

		type = MEMEORY_TYPE::INTERN;
		handle = GetModuleHandle(NULL);

		if (!handle) {
			Error(MEMEORY_CODE::PROCESS_NOT_FOUND);
			return;
		}

		initialized = true;
	};

	void Initialize(const char* window_name, const char* process_name) {
		type = MEMEORY_TYPE::EXTERN;

		DWORD pid = 0;
		HWND window = FindWindowA(NULL, window_name);

		if (!window) {
			Error(MEMEORY_CODE::PROCESS_NOT_FOUND);
			return; 
		}

		GetWindowThreadProcessId(window, &pid);

		if (!pid) {
			Error(MEMEORY_CODE::PROCESS_NOT_FOUND);
			return;
		}

		handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

		if (!handle) {
			Error(MEMEORY_CODE::PROCESS_NOT_FOUND);
			return;
		}

		initialized = true;
	};

	void Initialize(HANDLE handle_) {
		type = MEMEORY_TYPE::EXTERN;
		handle = handle_;

		initialized = true;
	};

	void* FindModule(const char* moduleName) {
		return GetModuleHandle(moduleName);
	}

	void* GetBaseAddress() {
		return FindModule(NULL);
	}

	MODULEINFO GetModuleInformation() {
		MODULEINFO info;
		HANDLE process = GetCurrentProcess();
		HMODULE mod = GetModuleHandle(NULL);

		GetModuleInformation(process, mod, &info, sizeof(info));

		return info;
	}

	size_t GetBaseSize() {
		MODULEINFO info = GetModuleInformation();

		return info.SizeOfImage;
	}

	bool IsSuccess() {
		return last_code == MEMEORY_CODE::SUCCESS;
	}

	bool IsFail() {
		return last_code == MEMEORY_CODE::FAIL;
	}

	void UnProtect(void* addr, size_t size, DWORD* save_protection) {
		if (IsExternal()) {
			VirtualProtectEx(handle, addr, size, PAGE_EXECUTE_READWRITE, save_protection);
		} else {
			VirtualProtect(addr, size, PAGE_EXECUTE_READWRITE, save_protection);
		}
	}

	void Protect(void* addr, size_t size, DWORD old_protection) {
		if (IsExternal()) {
			VirtualProtectEx(handle, addr, size, old_protection, &old_protection);
		} else {
			VirtualProtect(addr, size, old_protection, &old_protection);
		}
	}

	void Patch(void* addr, char byte, size_t size = 1) {
		if (!initialized) return;

		if (size == 1) {
			Write(addr, &byte, size);
		} else {
			char* buffer = new char[size];
			memset(buffer, byte, size);

			Write(addr, buffer, size);

			delete[] buffer;
		}
	}

	void Write(void* addr, void* buffer, size_t size) {
		SecureMemoryCall<InternalWrite>(addr, buffer, size);
	}

	void Read(void* addr, void* buffer, size_t size) {
		SecureMemoryCall<InternalRead>(addr, buffer, size);
	}

	void Nop(void* addr, size_t size) {
		Patch(addr, 0x90, size);
	}

	void* Offset(void* addr, size_t size) {
		return (void*)((ptr_t)addr + size);
	}

	bool IsInternal() {
		return type == MEMEORY_TYPE::INTERN;
	}

	bool IsExternal() {
		return type == MEMEORY_TYPE::EXTERN;
	}

	void Error(MEMEORY_CODE status) {
		last_code = status;

		auto it = MEMEORY_CODE_MESSAGE.find(status);
		auto error_message = (it == MEMEORY_CODE_MESSAGE.end() ? "Invalid error code" : it->second);

		MessageBox(NULL, error_message, "Memeory", 16L);
		//throw error_message;
	}

	code_t Absolutify(code_t stolen_code, void* gateway) {
		int     size = stolen_code.size;
		byte_t* code = stolen_code.bytes;

		HDE hs;
		int new_size = 0;
		int offset = 0;

		byte_t* temp_code = new byte_t[size * 4]; // 16/5 < 4 | size * 4 = maximum new_size

		while (offset < size) {
			void* actual_ptr = (void*)((ptr_t)code + offset); // todo: Offset()
			int instruction_size = HDE_DISASM((void*)actual_ptr, &hs);

			if (hs.flags & F_ERROR) {
				break;
			}
			else {
				void* actual_new_dimm = (void*)((ptr_t)actual_ptr + hs.len + hs.imm.imm32); // todo: Offset()
				void* actual_new_disp = (void*)((ptr_t)actual_ptr + hs.len + hs.disp.disp32); // todo: Offset()

				code_t actual_new_code;

				bool is_relative = hs.flags & F_RELATIVE;

				// Debugging
				 //std::cout << std::hex << (int)hs.opcode << " " << (int)hs.opcode2 << std::endl;
				 //std::cout << std::hex << (int)hs.modrm << " " << (int)hs.modrm_mod << " " << (int)hs.modrm_reg << " " << (int)hs.modrm_rm << std::endl;
				 //std::cout << std::hex << (int)hs.sib_base << " " << (int)hs.sib_index << " " << (int)hs.sib_scale << std::endl;
				 //std::cout << std::hex << (hs.flags & F_RELATIVE) << std::endl;
				 //std::cout << std::hex << actual_new_dimm << " " << actual_new_disp << std::endl;

				switch (hs.opcode) {

				case 0xE8: // rel call
					actual_new_code = call_t(gateway, actual_new_dimm).to_code(sizeof(call_t));
					break;

				case 0xE9: // rel jump
					actual_new_code = jump_t(gateway, actual_new_dimm).to_code(sizeof(jump_t));
					break;

				//case 0xFF:
					//if (hs.modrm == 0xA0) {
					//	actual_new_code = jump_t(gateway, actual_new_dimm).to_code(sizeof(jump_t));
					//	break;
					//}

				case 0x75: // rel conditionnal jump
					actual_new_code = jne_t(gateway, actual_new_dimm).to_code(sizeof(jne_t));
					break;

				case 0x74: // rel conditionnal jump

					actual_new_code = je_t(gateway, actual_new_dimm).to_code(sizeof(je_t));
					break;

				case 0x8D: // lea
					if (hs.modrm != 0x6C) {
						actual_new_code = mov_deref_t(gateway, actual_new_disp).to_code(sizeof(mov_deref_t));
						break;
					}

				case 0x8B: // rel mov
					if (hs.modrm == 0x05 || hs.modrm == 0x0D) {
						actual_new_code = mov_deref_t(gateway, actual_new_disp).to_code(sizeof(mov_deref_t));
						break;
					}

				case 0x83: // sub, cmp, ?
					if (hs.modrm == 0x3D) { // cmp
						actual_new_code = cmp_t(gateway, actual_new_disp).to_code(sizeof(cmp_t));
						break;
					}

				case 0x80: // sub, cmp, ?
					if (hs.modrm == 0x3D) { // cmp
						actual_new_code = cmp_t(gateway, actual_new_disp).to_code(sizeof(cmp_t));
						break;
					}

				default: // just copy the actual instruction, no need to absolutify

					if (is_relative) {
						Error(MEMEORY_CODE::DISASSEMBLER_FAILED);
					}

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

	bool IsJump(HDE hs) {

		auto op = hs.opcode;
		auto mod = hs.modrm;

		return (
			(op == 0xE9) ||
			(op == 0x75) ||
			(op == 0x74) ||
			(op == 0xFF && mod == 0x25)
		);
	}

	void* FollowJump(void* addr, int limit) {
		void* jump_addr  = addr;
		int   jump_count = 0;

		while (!limit || jump_count < limit) {

			HDE hs = Memory::Disassemble(jump_addr);

			if (Memory::IsJump(hs))  {
				if (hs.imm.imm32) {
					jump_addr = (void*)((ptr_t)jump_addr + hs.len + hs.imm.imm32); // todo: Offset()
				} else {
					jump_addr = (void*)((ptr_t)jump_addr + hs.len + hs.disp.disp32); // todo: Offset()
				}
			} else {
				return jump_addr;
			}

			jump_count++;
		}
	}

	HDE Disassemble(void* addr) {
		HDE hs;
		HDE_DISASM(addr, &hs);

		//if (hs.flags & F_ERROR) {
		//	Memory::Error(MEMEORY_CODE::DISASSEMBLER_FAILED);
		//}

		return hs;
	}

	int GetCodeSize(void* addr) {

		int size = 0;

		while (true) {

			auto hs = Disassemble((void*)((ptr_t)addr + size)); // todo: Offset()

			if (hs.opcode == 0xCC || hs.flags & F_ERROR) {
				break;
			} else {
				size += hs.len;
			}
		}

		return size;
	};
	
	int GetMinimumCodeSize(void* addr, int min_len) {

		int offset = 0;
		int offset_before_padding = 0;

		bool in_padding = false;

		while (offset < min_len) {

			auto hs = Disassemble((void*)((ptr_t)addr + offset)); // todo: Offset()

			if (hs.flags & F_ERROR) {
				break;
			} else {
				if (hs.opcode == 0xCC) {
					in_padding = true;
				} else {
					if (in_padding) break;
				}

				offset += hs.len;

				if (!in_padding) {
					offset_before_padding = offset;
				}
			}
		}

		if (offset < min_len) {
			return -1;
		}

		return offset_before_padding;
	};
}