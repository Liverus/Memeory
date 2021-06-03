#ifndef MEMEORY_H
#define MEMEORY_H

#include "windows.h"
#include <tchar.h>
#include <TlHelp32.h>

typedef unsigned char byte_t;

#if defined(_M_X64) || defined(__x86_64__)
	typedef unsigned long long ptr_t;
#else
	typedef unsigned int       ptr_t;
#endif

// Copypasted from forums, idk which one tho, it's a really common function anyway

struct Memory {
public:
		// General memory session vars
	bool external = true;
	HWND window;
	HDC dc;
	HANDLE handle;
	DWORD pid;
	MODULEENTRY32 module;
	ptr_t module_addr;
	size_t module_size;

	// FreeMem vars (trash)
	DWORD  free_dwOld = 0;
	void*  free_address;
	size_t free_size;

	Memory() {
		openprocess(NULL, NULL);
	};

	Memory(const char* window_name, const wchar_t* process_name) {
		openprocess(window_name, process_name);
	};

	MODULEENTRY32 dwGetModuleByName(const wchar_t* lpszModuleName, DWORD pID) {
		HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pID);
		MODULEENTRY32 ModuleEntry32 = { 0 };
		ModuleEntry32.dwSize = sizeof(MODULEENTRY32);

		if (Module32First(hSnapshot, &ModuleEntry32))
		{
			do {
				if (_tcscmp(ModuleEntry32.szModule, lpszModuleName) == 0)
				{
					break;
				}
			} while (Module32Next(hSnapshot, &ModuleEntry32));

		}

		CloseHandle(hSnapshot);

		return ModuleEntry32;
	}

	void* findmodule(const char* moduleName) {
		return GetModuleHandle((LPCWSTR)moduleName);
	}

	void* findfunction(const char* moduleName, const char* exportName) {
		HMODULE hMod = GetModuleHandleA(moduleName);
		void* src = GetProcAddress(hMod, exportName);

		return src;
	}

	bool success() {
		if (external) {
			return handle;
		} else {
			return true;
		}
	}

	bool openprocess(const char* window_name, const wchar_t* process_name) {

		if (window_name == NULL) {
			external = false;
			module_addr = (ptr_t)GetModuleHandle(NULL);
		} else {
			external = true;

			window = FindWindowA(NULL, window_name);
			dc = GetDC(window);
			GetWindowThreadProcessId(window, &pid);
			handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

			if (!handle)
			{
				return false;
			}

			module = dwGetModuleByName(process_name, pid);

			module_addr = (ptr_t)module.modBaseAddr;
			module_size = (size_t)module.modBaseSize;
		}

		return true;
	}

	void* offset(ptr_t addr) {
		if (!success()) return 0;

		return (void*)(module_addr + addr);
	}

	void free(void* addr, size_t size) {
		if (!success()) return;

		free_address = addr;
		free_size = size;

		if (external) {
			VirtualProtectEx(handle, free_address, free_size, PAGE_EXECUTE_READWRITE, &free_dwOld);
		}
		else {
			VirtualProtect(free_address, free_size, PAGE_EXECUTE_READWRITE, &free_dwOld);
		}
	}

	void unfree() {
		if (external) {
			VirtualProtectEx(handle, free_address, free_size, free_dwOld, &free_dwOld);
		}
		else {
			VirtualProtect(free_address, free_size, free_dwOld, &free_dwOld);
		}
	}

	//memset
	void patch(void* addr, char byte, size_t size) {
		if (!success()) return;

		if (!size) {
			size = 1;
		}

		free(addr, size);

		if (external) {
			void* buffer;

			if (size > 1) {
				void* barray = new char[size];
				memset(barray, byte, size);

				buffer = barray;
			}
			else {
				buffer = &byte;
			}

			WriteProcessMemory(handle, addr, buffer, size, NULL);
		} else {
			memset(addr, byte, size);
		}

		unfree();
	}

	//memcpy
	void write(void* addr, void* buffer, size_t size) {
		if (!success()) return;

		if (!size) {
			size = sizeof(buffer);
		}

		free(addr, size);

		if (external) {
			WriteProcessMemory(handle, addr, buffer, size, NULL);
		}
		else {
			memcpy(addr, buffer, size);
		}

		unfree();
	}

	void read(void* addr, void* buffer, size_t size) {
		if (!success()) return;

		if (!size) {
			size = sizeof(buffer);
		}

		free(addr, size);

		if (external) {
			ReadProcessMemory(handle, addr, buffer, size, NULL);
		}
		else {
			memcpy(buffer, addr, size);
		}

		unfree();
	}

	void nop(void* addr, size_t size) {
		if (!success()) return;

		free(addr, size);

		if (external) {
			patch(addr, 0x90, size);
		}
		else {
			memset(addr, 0x90, size);
		}

		unfree();
	}
};

#endif