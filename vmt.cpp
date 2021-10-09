#include "vmt.h"

VMT_Hook::VMT_Hook() {}

VMT_Hook::VMT_Hook(Memory memory_, void* vmt_, int index_, void* new_method_) {
	memory = memory_;
	index = index_;
	vmt = (ptr_t*)vmt_;
	new_method = (ptr_t)new_method_;
	original_method = vmt[index];
}

void VMT_Hook::load() {
	vmt[index] = new_method;
	loaded = true;
}

void VMT_Hook::unload() {
	vmt[index] = original_method;
	loaded = false;
}