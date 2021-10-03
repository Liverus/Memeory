#pragma once

#ifndef MEMEORY_H
#define MEMEORY_H

#include "windows.h"
#include <TlHelp32.h>
#include <tchar.h>

typedef unsigned char byte_t;

#if defined(_M_X64) || defined(__x86_64__)
	typedef unsigned long long ptr_t;
#else
	typedef unsigned int ptr_t;
#endif

struct Memory {
	Memory();
	Memory(const char* window_name, const wchar_t* process_name);

	// FUCK YOU I HATE CPP
	//template<class Function> Function find_function(const char* moduleName, const char* exportName);
	void* find_function(const char* moduleName, const char* exportName);

	void* find_module(const char* moduleName);
	bool  open_process(const char* window_name, const wchar_t* process_name);
	void* offset(ptr_t addr);

	void  unprotect(void* addr, size_t size, DWORD* save_protection);
	void  protect(void* addr, size_t size, DWORD old_protection);

	template<void(Method)(Memory mem, void*, void*, size_t)>
	void  secure_memory_call(void* addr, void* buffer, size_t size);

	void  patch(void* addr, char byte, size_t size);
	void  write(void* addr, void* buffer, size_t size);
	void  read(void* addr, void* buffer, size_t size);
	void  nop(void* addr, size_t size);

	bool external;
	HWND window;
	HDC dc;
	HANDLE handle;
	DWORD pid;
	MODULEENTRY32 module;
	ptr_t module_addr;
	size_t module_size;

	bool success();
	bool initialized = false;
};

void _write(Memory mem, void* addr, void* buffer, size_t size);
void _read(Memory mem, void* addr, void* buffer, size_t size);

#endif