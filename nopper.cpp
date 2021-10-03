#include "nopper.h"

Nopper::Nopper() {};

Nopper::Nopper(Memory memory, void* target_addr, void* buffer, int buffer_size) {
	inilialize(memory, target_addr, buffer, buffer_size);
}

void Nopper::inilialize(Memory memory_, void* target_addr_, void* buffer_, int payload_size_) {
	memory = memory_;
	address = target_addr_;
	payload = buffer_;
	payload_size = payload_size_;
};

void Nopper::load() {
	memory.patch(address, 0x90, payload_size);
	loaded = true;
};

void Nopper::unload() {
	memory.write(address, payload, payload_size);
	loaded = false;
};

void Nopper::set(bool a) {
	if (a) {
		load();
	}
	else {
		unload();
	}
};

void Nopper::toggle()
{
	set(!loaded);
};