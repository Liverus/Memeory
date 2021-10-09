#include "vmt.h"
#include <iostream>

VMT::VMT() {}
VMT::~VMT() {
	delete[] original_vmt;
}

VMT::VMT(Memory memory, void* addr) {
	initialize(memory, addr, count_methods(addr));
}

void VMT::initialize(Memory memory_, void* address, size_t size_) {
	memory = memory_;
	size = size_;
	vmt = (ptr_t*)address;

	original_vmt = new ptr_t[size];

	// Copy the original VMT
	memory.read(address, original_vmt, size_);
}

//VMT_Hook VMT::create_hook(int index, void * new_method)
//{
//	return VMT_Hook(*this, index, new_method);
//}

size_t VMT::count_methods(void* address) {
	size_t i = 0;

	while (((ptr_t*)address)[i++]);

	return i;
}

VMT_Hook::VMT_Hook() {}

VMT_Hook::VMT_Hook(VMT vmt_obj_, int index_, void* new_method_) {
	vmt_obj = vmt_obj_;
	index = index_;
	new_method = new_method_;
}

void VMT_Hook::load() {
	vmt_obj.vmt[index] = (ptr_t)new_method;
	loaded = true;
}

void VMT_Hook::unload() {
	vmt_obj.vmt[index] = vmt_obj.original_vmt[index];
	loaded = false;
}