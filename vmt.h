#pragma once

#ifndef VMT_H
#define VMT_H

#include "memeory.h"

struct VMT_Hook {

	VMT_Hook();
	VMT_Hook(Memory memory_, void* vmt_, int index_, void* new_method_);

	void load();
	void unload();

	template<typename T>
	T get_original() {
		return (T)(void*)original_method;
	}

	Memory memory;
	ptr_t* vmt;
	ptr_t new_method;
	ptr_t original_method;
	int index;
	bool loaded = false;
};

#endif