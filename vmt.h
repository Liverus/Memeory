#pragma once

#include "memeory.h"

namespace Memory {

	template<typename T>
	T VMT_Method(void* vtable, int index) {
		return (*(T**)vtable)[index]; // you're awesome!!!
	}

	class VMT_Hook {
	public:
		VMT_Hook();
		VMT_Hook(void* vmt_, int index_, void* new_method_, void* original_copy_=0);

		static void UnloadAll();

		void Load();
		void Unload();

		template<typename T>
		T GetOriginal() {
			return (T)original_method;
		}

		void** vmt;
		void* new_method;
		void* original_method;
		int index;

		bool loaded = false;

		static std::vector<VMT_Hook> list;
	};
}