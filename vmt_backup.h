#pragma once

#ifndef VMT_H
#define VMT_H

#include "memeory.h"

struct VMT {

	VMT();
	VMT(Memory memory, void* address_);
	~VMT();

	void initialize(Memory memory, void* addr, size_t size);
	//VMT_Hook create_hook(int index, void* new_method);

	static size_t count_methods(void* address);

	Memory memory;
	ptr_t* original_vmt;
	ptr_t* vmt;
	size_t size;
};

struct VMT_Hook {
	VMT_Hook();
	VMT_Hook(VMT vmt_obj_, int index_, void* new_method_);

	template<typename T>
	T get_original() {
		return (T)vmt_obj.original_vmt[index];
	}

	void  load();
	void  unload();

	void* new_method;
	int index;
	VMT vmt_obj;
	bool loaded = false;
};

#endif