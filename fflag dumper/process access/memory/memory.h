class Driver {
public:
	DWORD vm_procid = 0;
	HANDLE vm_hprocid = INVALID_HANDLE_VALUE;

	bool vm_attach(DWORD pid) {
		vm_hprocid = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
		if (vm_hprocid) {
			vm_procid = pid;
			return true;
		}
		return false;
	}

	DWORD vm_getpid(const std::wstring& name) {
		PROCESSENTRY32W pe{ };
		pe.dwSize = sizeof(pe);

		HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (snap == INVALID_HANDLE_VALUE)
			return 0;

		if (Process32FirstW(snap, &pe)) {
			do {
				if (name == pe.szExeFile) {
					CloseHandle(snap);
					return pe.th32ProcessID;
				}
			} while (Process32NextW(snap, &pe));
		}

		CloseHandle(snap);
		return 0;
	}

	uintptr_t vm_getmodulebase(const std::wstring& name) {
		MODULEENTRY32W me{ };
		me.dwSize = sizeof(me);

		HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, vm_procid);
		if (snap == INVALID_HANDLE_VALUE)
			return 0;

		if (Module32FirstW(snap, &me)) {
			do {
				if (!_wcsicmp(name.c_str(), me.szModule)) {
					CloseHandle(snap);
					return (uintptr_t)me.modBaseAddr;
				}
			} while (Module32NextW(snap, &me));
		}

		CloseHandle(snap);
		return 0;
	}

	template<typename T>
	T vm_read(uintptr_t addr) {
		T val{ };
		ReadProcessMemory(vm_hprocid, (LPCVOID)addr, &val, sizeof(T), nullptr);
		return val;
	}

	bool vmread_raw(uintptr_t addr, void* buffer, size_t size) {
		SIZE_T bytes;
		return ReadProcessMemory(vm_hprocid, (LPCVOID)addr, buffer, size, &bytes) && bytes == size;
	}

	template<typename T>
	bool vm_write(uintptr_t addr, const T& val) {
		SIZE_T bytes;
		return WriteProcessMemory(vm_hprocid, (LPVOID)addr, &val, sizeof(T), &bytes);
	}

	std::string readstring(uintptr_t addr) {
		int len = vm_read< int >(addr + 0x18);
		if (len <= 0 || len > 1000)
			return "";

		uintptr_t data = addr;
		if (len >= 16) {
			data = vm_read< uintptr_t >(addr);
			if (!data) return "";
		}

		std::string str(len, '\0');
		if (!vmread_raw(data, &str[0], len))
			return "";

		if (auto pos = str.find('\0'); pos != std::string::npos)
			str.resize(pos);

		return str;
	}

	static inline bool vm_isvalid(uintptr_t p) {
		return p > 0x10000 && p < 0x7FFFFFFFFFFFULL;
	}

	static bool vm_isvalidname(const std::string& s) {
		if (s.size() < 3 || s.size() > 200) return false;
		if (!isalpha((unsigned char)s[0])) return false;
		for (char c : s)
			if (!isalnum((unsigned char)c) && c != '_') return false;
		return true;
	}
};

inline Driver driver;