#include "memeory.h"

// Copypasted from forums, idk which one tho
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

void _write(Memory mem, void* addr, void* buffer, size_t size) {
	if (mem.external) {
		WriteProcessMemory(mem.handle, addr, buffer, size, NULL);
	}
	else {
		memcpy(addr, buffer, size); //todo: rewrite memcpy so it's not imported anymore -> less detected?
	}
}

void _read(Memory mem, void* addr, void* buffer, size_t size) {
	if (mem.external) {
		ReadProcessMemory(mem.handle, addr, buffer, size, NULL);
	}
	else {
		memcpy(buffer, addr, size);
	}
}

Memory::Memory() {
	open_process(NULL, NULL);
};

Memory::Memory(const char* window_name, const wchar_t* process_name) {
	open_process(window_name, process_name);
};

void* Memory::find_module(const char* moduleName) {
	return GetModuleHandleA(moduleName);
}

bool Memory::success() {
	return initialized;
}

bool Memory::open_process(const char* window_name, const wchar_t* process_name) {

	if (window_name == NULL) {          
		external = false;               
		module_addr = (ptr_t)GetModuleHandle(NULL);
	} else { // yeah i was planning on making it both external and internal (because i started doing external)
			 // but now i know that external memory patching is trash so..
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

		module_addr =  (ptr_t)module.modBaseAddr;
		module_size = (size_t)module.modBaseSize;
	}

	initialized = true;

	return true;
}

void* Memory::offset(ptr_t addr) {
	if (!success()) return 0;

	return (void*)(module_addr + addr);
}

void Memory::unprotect(void* addr, size_t size, DWORD* save_protection) {
	if (!success()) return;

	if (external) {
		VirtualProtectEx(handle, addr, size, PAGE_EXECUTE_READWRITE, save_protection);
	}
	else {
		VirtualProtect(addr, size, PAGE_EXECUTE_READWRITE, save_protection);
	}
}

void Memory::protect(void* addr, size_t size, DWORD old_protection) {
	if (!success()) return;

	if (external) {
		VirtualProtectEx(handle, addr, size, old_protection, &old_protection);
	} else {
		VirtualProtect(addr, size, old_protection, &old_protection);
	}
}

void Memory::patch(void* addr, char byte, size_t size=1) {
	if (!success()) return;

	char* buffer;

	if (size > 1) {
		char* barray = new char[size]; // mem leak pls
		memset(barray, byte, size);

		buffer = barray;
	} else {
		buffer = &byte;
	}

	secure_memory_call<_write>(addr, buffer, size);
}

void Memory::write(void* addr, void* buffer, size_t size) {
	if (!success()) return;

	secure_memory_call<_write>(addr, buffer, size);
}

void Memory::read(void* addr, void* buffer, size_t size) {
	if (!success()) return;

	secure_memory_call<_read>(addr, buffer, size);
}

void Memory::nop(void* addr, size_t size) {
	if (!success()) return;

	patch(addr, 0x90, size);
}
