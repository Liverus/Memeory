#pragma once

#include "memeory.h"

namespace Memory {

	struct op {
		code_t to_code(size_t size) {
			return code_t((byte_t*)this, size);
		}
	};

	struct x32_jump : op {
		x32_jump() {};
		x32_jump(void* src, void* addr) {
			int delta = (ptr_t)addr - (ptr_t)src - sizeof(x32_jump);

			memcpy(address, &delta, sizeof(address));
		};

		byte_t opcode = 0xE9;
		byte_t address[4];
	};

	struct x64_jump : op {
		x64_jump() {};
		x64_jump(void* src, void* addr) {
			memcpy(address, &addr, sizeof(address));
		};

		byte_t opcode[6] = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00 };
		byte_t address[8];
	};

	struct x32_call : op {
		x32_call() {};
		x32_call(void* src, void* addr) {
			int delta = (ptr_t)addr - (ptr_t)src - sizeof(x32_call);

			memcpy(address, &delta, sizeof(address));
		};

		byte_t opcode = 0xE8;
		byte_t address[4];
	};

	struct x64_call : op {
		x64_call() {};
		x64_call(void* src, void* addr) {
			memcpy(address, &addr, sizeof(address));
		};

		byte_t opcode[8] = { 0xFF, 0x15, 0x02, 0x00, 0x00, 0x00, 0xEB, 0x08 };
		byte_t address[8];
	};


	struct x32_mov : op {
		x32_mov() {};
		x32_mov(void* src, void* addr) {
			memcpy(address, &addr, sizeof(address));
		};

		byte_t opcode[2] = { 0x48, 0xB8 };
		byte_t address[4];
	};

	struct x64_mov : op {
		x64_mov() {};
		x64_mov(void* src, void* addr) {
			memcpy(address, &addr, sizeof(address));
		};

		byte_t opcode[2] = { 0x48, 0xB8 };
		byte_t address[8];
	};

	struct x64_mov_deref : op {
		x64_mov_deref() {};
		x64_mov_deref(void* src, void* addr) {
			memcpy(address, &addr, sizeof(address));
		};

		byte_t opcode[2] = { 0x48, 0xA1 };
		byte_t address[8];
	};

#if defined(_M_X64) || defined(__x86_64__)
	typedef x64_jump jump_t;
	typedef x64_call call_t;
	typedef x64_mov mov_t;

	typedef x64_mov_deref mov_deref_t;
#else
	typedef x32_jump jump_t;
	typedef x32_call call_t;
	typedef x32_mov mov_t;

	typedef x64_mov_deref mov_deref_t;
#endif

	struct x64_je : op {
		x64_je() {};
		x64_je(void* src, void* addr) {
			jmp = jump_t(src, addr);
			byte_t sz = sizeof(jmp);

			memcpy(&offset, &sz, sizeof(offset));
		};

		byte_t opcode = 0x75; //74 = Je | 75 = Jne (Inverted)
		byte_t offset;
		jump_t   jmp;
	};

	struct x64_jne : op {
		x64_jne() {};
		x64_jne(void* src, void* addr) {
			jmp = jump_t(src, addr);
			byte_t sz = sizeof(jmp);

			memcpy(&offset, &sz, sizeof(offset));
		};

		byte_t opcode = 0x74; //74 = Je | 75 = Jne (Inverted)
		byte_t offset;
		jump_t   jmp;
	};

	typedef x64_je je_t;
	typedef x64_jne jne_t;

	struct x64_cmp : op {
		x64_cmp() {};
		x64_cmp(void* src, void* addr) {
			mov = mov_t(src, addr);
		};

		byte_t push_eax = 0x50;
		mov_t mov;
		byte_t test_eax[3] = { 0x48, 0x85, 0xC0 }; // BAD, NEED TO CMP EAX, imm
		byte_t pop_eax = 0x58;

		// Before:
			// cmp qword ptr [annoying_relative_address], imm

		// After:
			// push eax
			// mov eax, good_absolute_address :D
			// test eax, eax <-- BAD, NEED TO FIX
			// pop eax
	};

	typedef x64_cmp cmp_t;

	class Hook {
	public:
		Hook();
		Hook(void* src_address, void* target_address, void* original_copy=0);
		Hook(void* src_address, int index, void* target_address, void* original_copy = 0);
		Hook(const char* module_name, const char* export_name, void* target_address, void* original_copy=0);

		static void UnloadAll();

		void Initialize(void* src_addr_, void* target_addr_, void* original_address_);
		void SetupJumps();

		template<typename T>
		T GetOriginal()
		{
			if (loaded) {
				return (T)gateway;
			}

			return 0;
		}

		void* GetOriginal();
		void  Load();
		void  Unload();

		bool  loaded;

		void* original_address;
		void* target_address;
		void* src_address;
		void* gateway;

		int   func_size;
		int   minimum_size;

		jump_t  jump_forward;
		jump_t  jump_backward;

		code_t original_code;

		static std::vector<Hook> list;
	};
}