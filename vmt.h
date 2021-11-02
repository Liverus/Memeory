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
		return (T)original_method;
	}

	Memory memory;
	void** vmt;
	void* new_method;
	void* original_method;
	int index;
	bool loaded = false;
};

#endif