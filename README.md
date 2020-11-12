# reverse-injector

Inject a process into your context. You can call functions that do not reference absolute virtual addresses. Reverse injector copies a target processes pml4e's into another specified 
processes pml4. Current the project copies the targets pml4e's into the current process (reverse-injector.exe), but you can configure the project to inject a process into any process
you want.

# Info

```
VDM ---> PTM ---> reverse-injector
```

The project uses PTM which uses VDM. Althought VDM is utilized in this project you do not need to have VDM's vulnerable driver loaded into the kernel when creating an `injector_ctx`. 
As you can see in the demo I have modified VDM to change how it reads and writes to physical memory. I make VDM use a mem_ctx object to read/write physical memory. (mem_ctx is PTM). 
PTM manages its own set of paging tables from usermode and does not need a vulnerable driver after it has been initalized. 

# Heap Memory?

All memory in the process being reverse injected is mapped into the target process, this includes heap memory. When memory is allocated in PDPT's, PD's, and PT's the memory is also
mapped into the process that was reverse injected into. This is because both processes PML4E's point to the same PDPT's. 

If another PML4E is inserted into the process that was reverse injected I have a try catch around `nasa::injector_ctx::translate` that will copy the new PML4E into the target process
and thus keep the PML4's synced.