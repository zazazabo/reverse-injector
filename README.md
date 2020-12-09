<div align="center">
    <img src="https://i.imgur.com/m4lOGSJ.png"/>
</div>

# Reverse Injector

Inject a process into your context. Reverse injector copies a target processes PML4E's into another specified 
processes PML4. Currently the project copies the target processes PML4E's into the current process PML4 (reverse-injector.exe), but you can configure the project to inject a process into any process
you want.

# Info

```
VDM ---> PTM ---> reverse-injector
```

The project uses PTM which uses VDM. Althought VDM is utilized in this project you do not need to have VDM's vulnerable driver loaded into the kernel when creating an `injector_ctx`. 
As you can see in the demo I have modified VDM to change how it reads and writes to physical memory. I make VDM use a mem_ctx object to read/write physical memory. (mem_ctx is PTM). 
PTM manages its own set of paging tables from usermode and does not need a vulnerable driver after it has been initalized. 

# Heap Memory?

All memory in the process being reverse injected is mapped into the target process, this includes heap memory (mapping is NOT allocating its pointing at the same physical memory! so if something changes in the game, it changes in your context). When memory is allocated in PDPT's, PD's, and PT's the memory is also
mapped into the process that was reverse injected into. This is because both processes PML4E's point to the same PDPT's. 

If another PML4E is inserted into the process that was reverse injected I have a try catch around `nasa::injector_ctx::translate` that will copy the new PML4E into the target process
and thus keep the PML4's synced.

# Calling Functions?

You can call functions that do not reference absolute addresses. This last sentence is pretty ambigous but in short, when the process is injected into another the space between the PML4E's
is not the same (nor is the PML4E index the same).

My suggestion is you call only small functions if you want to call functions. 

# Example

Since all of the games memory is mapped into your process you can simply walk the games PEB for loaded modules. Here is an example of how to do that.

```cpp
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

	const auto list_head = &ldr_data->InMemoryOrderModuleList;
	while (current_entry != list_head)
	{
		const auto current_entry_data =
			reinterpret_cast<PLDR_DATA_TABLE_ENTRY>(
				reinterpret_cast<std::uintptr_t>(current_entry) - sizeof LIST_ENTRY);

		const auto entry_module_name =
			reinterpret_cast<const wchar_t*>(
				rinjector->translate(
					reinterpret_cast<std::uintptr_t>(
						reinterpret_cast<PUNICODE_STRING>(
							reinterpret_cast<std::uintptr_t>(
								&current_entry_data->FullDllName) + sizeof UNICODE_STRING)->Buffer)));

		if (!_wcsicmp(entry_module_name, module_name))
			return reinterpret_cast<std::uintptr_t>(current_entry_data->DllBase);

		current_entry = reinterpret_cast<LIST_ENTRY*>(
			rinjector->translate(reinterpret_cast<std::uintptr_t>(current_entry->Flink)));
	}
	return {};
}
```