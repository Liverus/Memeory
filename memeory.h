#pragma once

#include "windows.h"
#include "psapi.h"

#include <TlHelp32.h>
#include <tchar.h>
#include <map>
#include <vector>
#include <iostream>

typedef unsigned char byte_t;

#define INRANGE(x,a,b)  (x >= a && x <= b) 
#define getBits( x )    (INRANGE((x&(~0x20)),'A','F') ? ((x&(~0x20)) - 'A' + 0xa) : (INRANGE(x,'0','9') ? x - '0' : 0))
#define getByte( x )    (getBits(x[0]) << 4 | getBits(x[1]))

#if defined(_M_X64) || defined(__x86_64__)
	typedef unsigned long long ptr_t;
	#include "hde64.h"
	typedef hde64s HDE;
	#define HDE_DISASM(code, hs) hde64_disasm(code, hs)
	#define MEMEORY_X64
#else
	typedef unsigned int ptr_t;
	#include "hde32.h"
	typedef hde32s HDE;
	#define HDE_DISASM(code, hs) hde32_disasm(code, hs)
	#define MEMEORY_X32
#endif

enum class MEMEORY_TYPE : int
{
	INTERN,
	EXTERN
};

enum class MEMEORY_CODE : int
{
	SUCCESS,
	FAIL,
	ADMIN_PRIVILEGE_REQUIRED,
	PROCESS_NOT_FOUND,
	WRITE_MEMORY,
	READ_MEMORY,
	HOOK_MISSING_SPACE,
	ALLOCATION_FAILED,
	DISASSEMBLER_FAILED
};

namespace Memory {
	struct code_t {
		code_t() {};
		code_t(byte_t* bytes_, int size_) {
			bytes = bytes_;
			size = size_;
		};

		void free() { // i don't know what i'm doing pls help
			delete[size] bytes;
		}

		byte_t* bytes;
		int size;
	};

	extern bool initialized;

	extern const std::map<MEMEORY_CODE, const char*> MEMEORY_CODE_MESSAGE;

	void  Initialize();
	void  Initialize(HANDLE handle_);
	void  Initialize(const char* window_name, const char* process_name);

	void  InternalWrite(void* addr, void* buffer, size_t size);
	void  InternalRead(void* addr, void* buffer, size_t size);

	void* GetBaseAddress();
	MODULEINFO GetModuleInformation();
	size_t GetBaseSize();
	void* FindModule(const char* moduleName=NULL);

	void  Patch(void* addr, char byte, size_t size);
	void  Write(void* addr, void* buffer, size_t size);
	void  Read(void* addr, void* buffer, size_t size);
	void  Nop(void* addr, size_t size);

	void  UnProtect(void* addr, size_t size, DWORD* save_protection);
	void  Protect(void* addr, size_t size, DWORD old_protection);

	bool   IsJump(HDE hs);
	void*  FollowJump(void* addr, int limit = 0);
	HDE    Disassemble(void* addr);
	code_t Absolutify(code_t stolen_code, void* gateway);
	int    GetCodeSize(void* addr);
	int    GetMinimumCodeSize(void* addr, int min_len);

	void Error(MEMEORY_CODE status);

	bool IsInternal();
	bool IsExternal();

	// Pasted

	template <class T>
	T FindPattern(const char* module_name, const char* signature) {
		MODULEINFO modInfo;
		GetModuleInformation(GetCurrentProcess(), GetModuleHandleA(module_name), &modInfo, sizeof(MODULEINFO));
		ptr_t startAddress = reinterpret_cast<ptr_t>(modInfo.lpBaseOfDll);
		ptr_t endAddress = startAddress + modInfo.SizeOfImage;
		const char* pat = signature;
		ptr_t firstMatch = 0;
		for (ptr_t pCur = startAddress; pCur < endAddress; pCur++)
		{
			if (!*pat) return (T)firstMatch;
			if (*(PBYTE)pat == '\?' || *(BYTE*)pCur == getByte(pat))
			{
				if (!firstMatch) firstMatch = pCur;
				if (!pat[2]) return (T)firstMatch;
				if (*(PWORD)pat == '\?\?' || *(PBYTE)pat != '\?') pat += 3;
				else pat += 2;
			}
			else
			{
				pat = signature;
				firstMatch = 0;
			}
		}

		return NULL;
	}

	template<class T>
	T FindFunction(void* mod, const char* export_name) {
		void* src = GetProcAddress((HMODULE)mod, export_name);

		return (T)src;
	}

	template<class T>
	T FindFunction(const char* module_name, const char* export_name) {
		HMODULE mod = GetModuleHandleA(module_name);

		return FindFunction<T>(mod, export_name);
	}

	template<class T>
	T CopyFunction(void* addr) {
		size_t size = GetCodeSize(addr);

		void* new_code = VirtualAlloc(0, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

		code_t absolute = Absolutify(code_t((byte_t*)addr, size), new_code);

		Memory::Write(new_code, absolute.bytes, absolute.size);

		absolute.free();

		return (T)new_code;
	}

	template<void(*T)(void*, void*, size_t)>
	void SecureMemoryCall(void* addr, void* buffer, size_t size) {
		if (!initialized) return;

		DWORD old_protection = 0;

		UnProtect(addr, size, &old_protection);
		T(addr, buffer, size);
		Protect(addr, size, old_protection);
	}

	// Error Handling
	extern MEMEORY_TYPE type;
	extern MEMEORY_CODE last_code;

	// Handle
	extern HANDLE handle;
};

#include "hook.h"
#include "vmt.h"