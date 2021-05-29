#ifndef NOPPER_H
#define NOPPER_H

#include "mem.hpp"

struct Nopper {

	bool   loaded = false;
	void*  address;
	void*  payload;
	int    payload_size;

	Memory memory;

	Nopper() {};
	Nopper(Memory memory, void* target_addr, void* buffer, int buffer_size) {
		setup(memory, target_addr, buffer, buffer_size);
	};

	void setup(Memory memory_, void* target_addr_, void* buffer_, int buffer_size_) {
		address      = target_addr_;
		payload      = buffer_;
		payload_size = buffer_size_;
		memory       = memory_;
	};

	void set(bool a) {
		if (a) {
			load();
		}
		else {
			unload();
		}
	};

	void load() {
		memory.patch(address, 0x90, payload_size);
		loaded = true;
	};

	void unload() {
		memory.write(address, payload, payload_size);
		loaded = false;
	};

	void toggle()
	{
		if (loaded) {
			unload();
		}
		else {
			load();
		}
	};
};
#endif