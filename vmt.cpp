#include "vmt.h"

namespace Memory {
	VMT_Hook::VMT_Hook() {}

	VMT_Hook::VMT_Hook(void* vmt_, int index_, void* new_method_, void* orignal_copy_) {
		index = index_;
		new_method = new_method_;

		vmt = *((void***)vmt_);

		original_method = vmt[index];

		*(void**)orignal_copy_ = original_method;
	}

	void VMT_Hook::Load() {
		Memory::Write(&vmt[index], &new_method, sizeof(new_method));
		loaded = true;
	}

	void VMT_Hook::Unload() {
		Memory::Write(&vmt[index], &original_method, sizeof(original_method));
		loaded = false;
	}
}