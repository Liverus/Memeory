#pragma once

#ifndef NOPPER_H
#define NOPPER_H

#include "memeory.h"

struct Nopper {
	Nopper();
	Nopper(Memory memory, void* target_addr, void* buffer, int buffer_size);

	void inilialize(Memory memory_, void* target_addr_, void* buffer_, int buffer_size_);
	void set(bool a);
	void load();
	void unload();
	void toggle();

	Memory memory;
	bool   loaded = false;
	void*  address;
	void*  payload;
	int    payload_size;
};

#endif