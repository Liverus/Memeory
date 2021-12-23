#include "vmt.h"

VMT_Hook::VMT_Hook() {}

VMT_Hook::VMT_Hook(Memory memory_, void* vmt_, int index_, void* new_method_) {
	memory = memory_;
	index = index_;
	new_method = new_method_;

	vmt = *((void***)vmt_);

	original_method = vmt[index];
}

void VMT_Hook::load() {
	memory.write(&vmt[index], &new_method, sizeof(new_method));
	loaded = true;
}

void VMT_Hook::unload() {
	memory.write(&vmt[index], &original_method, sizeof(original_method));
	loaded = false;
}