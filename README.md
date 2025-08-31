# VAC-Module-Dumper

## Introduction

Valve Anti-Cheat (VAC) is Valve’s proprietary security system designed to detect and mitigate cheating in its multiplayer titles, most prominently within the Counter-Strike franchise. At the core of its operation is **steamservice.dll**, a dynamic link library responsible for handling the initialization and execution of VAC’s routines.

How this library is loaded depends on the privilege level at which Steam is launched:  
- When Steam runs without administrative rights, **steamservice.dll** is executed by **SteamService.exe**.  
- When Steam is launched with elevated privileges, the DLL is instead loaded directly by **steam.exe**.

This difference is not trivial but a fundamental architectural choice. It is crucial for dumping modules in the way I will explain, because you need to pick the second option—running Steam as administrator—so that **steam.exe** directly loads **steamservice.dll**.

---

## Why is it important how Steam loads its modules?

Anyone interested in bypassing even a basic anti-cheat system knows that the first step is to reverse engineer its logic and understand the checks it performs. To bypass an anti-cheat, you first need to reverse it. But… what happens if those modules never touch disk and are streamed directly from the server?

In that case, reverse engineering the anti-cheat modules is not straightforward. The approach then is to locate where those modules are loaded in memory and understand exactly how the program maps them. I will show you the logic Valve applies to stream and map these modules, and how we can take advantage of the control flow to dump them in the easiest possible way.

We will also look at some of the routines the loader uses for integrity checks, as well as the internal structures Valve defines to handle those modules.

## How VAC Modules Work

Unlike static anti-cheat implementations, VAC does not embed all detection logic within the game binary. Instead, **VAC modules are streamed dynamically from Valve’s servers**, allowing Valve to deliver targeted updates and continuously adapt its detection capabilities.

Each streamed module encapsulates detection algorithms, integrity verification routines, and system interrogation logic. The VAC client dynamically integrates these modules during runtime.

The system can be summarized as follows:  
- **Server-side (Valve infrastructure):** Decides which modules to stream to a client based on contextual factors such as game, environment, or suspicious patterns.  
- **Client-side (VAC core):** Receives, validates, maps, and executes the streamed modules in a controlled environment.  
- **Security model:** Dynamic streaming prevents reverse engineers from relying on static binaries, enabling Valve to iterate rapidly on detection methods while reducing the attack surface.

This architecture ensures VAC remains agile against evolving cheat techniques and maintains a hardened defensive posture.

---

## The Routine Responsible for Loading

The orchestration of VAC’s streamed modules is handled within **steamservice.dll**. A key observation is that every module delivered from Valve’s servers shares a common feature: each exports a function named **"_runfunc@20"**. This function serves as the standard entry point invoked by **steamservice.dll** to execute the module, typically within its own dedicated thread. The presence of this export can also be confirmed by inspecting the DLL’s strings, as shown in the screenshots.

![RunFunc Export](images/runfunc.png)

Following this string reference leads us directly to the routine responsible for handling module loading.

---

## Module Loading Routine

The pseudocode below outlines the logic of the `sub_6F6E8FD0` function. The decompilation has been cleaned up and annotated to highlight inferred types and identified routines.

During reverse engineering, one of the first notable findings is that Valve uses a dedicated structure to store metadata for each streamed module. This structure is defined as follows:

```cpp
00000000 struct __fixed VLV_STRUCT // sizeof=0x20
00000000 {
00000004     uint32_t h_field;
00000008     char allocated_heap;
0000000C     char runfunc_address;
00000010     uint32_t state_code;
00000014     uint32_t buffer_size;
00000018     IMAGE_DOS_HEADER *dos_header;
00000020 };
```

The structure is passed as the first argument to the function and maintains all relevant module information throughout the loading routine. The second argument acts as a flag that determines the execution flow, as there are two major paths in the routine.

<p align="center">
  <img src="images/graph.png" alt="Control Graph" width="700"/>
</p>

These two flows correspond to the two primary methods Valve employs to load streamed modules. The first method is **manual mapping**: after mapping the module into memory, the loader retrieves the exported entry point "_runfunc@20" and stores it in the `VLV_STRUCT` instance. The `manual_map` function performs several key operations, which are discussed in detail later.

```cpp
if ( (module_flags & 2) != 0 )              // Manual mapping module load
{
    heap_ptr = manual_map(ValveStruct_2->dos_header, 0, 1);
    *&ValveStruct_2->allocated_heap = heap_ptr;
    if ( heap_ptr )
    {
        exported_address = get_exported_address(heap_ptr, "_runfunc@20");
        *&ValveStruct_2->runfunc_address = exported_address;
        if ( !exported_address )
            ValveStruct_2->state_code = runfunc_function_not_found;
    }
    else
    {
        ValveStruct_2->state_code = module_not_allocated;
    }
}
```

The alternative control flow is the standard file-based module load using `LoadLibrary`. Notably, this path requires the module to exist on disk, which introduces a tangible point of access that we can exploit for interception and analysis.

```cpp
else                                        // File based module load
    {
      ValveStruct = 0;
      sub_6F7077B0(&v19);
      ValveStruct_2->state_code = 0;
      if ( create_temporal_file(&ValveStruct) )
      {
        sub_6F7091D0(&v19, ValveStruct_2->dos_header, ValveStruct_2->buffer_size, ValveStruct_2->buffer_size, 0);
        valve_struct = &pszSubKey;
        v10 = &pszSubKey;
        if ( ValveStruct )
          v10 = ValveStruct;
        if ( write_module_to_file(&v19, v10, 0) )
        {
          v11 = &pszSubKey;
          if ( ValveStruct )
            v11 = ValveStruct;
          sub_6F707310(&ValveStruct_2[1].allocated_heap, v11);
          if ( ValveStruct )
            valve_struct = ValveStruct;
          library = load_library(valve_struct, 0);
          ValveStruct_2->h_field = library;
          if ( library )
          {
            exported_address_disk = get_exported_address_disk(library, "_runfunc@20");
            *&ValveStruct_2->runfunc_address = exported_address_disk;
            if ( !exported_address_disk )
              ValveStruct_2->state_code = runfunc_function_not_found_disk;
          }
          else
          {
            ValveStruct_2->state_code = 22;
          }
        }
        else
        {
          ValveStruct_2->state_code = 21;
        }
        if ( v21 >= 0 )
        {

            . . .
          
        }
        v15 = sub_6F779360();
        (*(*v15 + 28))(v15, ValveStruct, 0);
      }
      else
      {

            . . .
          
      }
    } 
```
Knowing this, and considering that the second execution path drops the module into the user's temporary folder, we only need to trigger that path. Let’s examine the condition that controls this branch and observe how it appears in the disassembler and the debugger.

<p align="center">
  <img src="images/branch_condition.png" alt="Branch condition" width="1000"/>
</p>

<p align="center">
  <img src="images/x64_pre_patch.png" alt="Branch condition" width="1000"/>
</p>

Knowing this, we coded a C++ program that attaches to the target process, resolves the base address of `steamservice.dll`, and modifies the instruction at the conditional jump. The patch forces the branch to always be taken, effectively making the loader use the disk-based code path every time.

In the unmodified binary, the sequence looks like this:
```
test    [ebp+drop_mod_on_disk], 2
jz       short loc_6F6E90B7
```
We will replace it with this sequence of bytes:
```
nop
nop
test    eax, eax
```
This ensures the jump is always performed, guaranteeing that every streamed module is materialized on disk prior to being mapped into memory using the LoadLibrary flow and not the manual mapping one.

<p align="center">
  <img src="images/x64_post_patch.png" alt="Branch condition" width="1000"/>
</p>

To test the patch, start Steam with administrative privileges and then run the patching utility, also as administrator, so it can modify the target process. Once applied, the utility confirms the memory modification of the conditional branch. With the patch active, launch a VAC-protected game like Counter-Strike 2.

Using Process Monitor, you can observe the patched loader consistently writing the streamed module binaries to Steam's temporary directory. Within moments of joining a multiplayer game, these modules appear as actual files in the temp folder, ready for inspection and reverse engineering. The images below show the streamed modules and their persistence on disk after the patch.

<p align="center">
  <img src="images/modules_streamed.png" alt="Branch condition" width="1000"/>
</p>

<p align="center">
  <img src="images/modules_on_disk.png" alt="Branch condition" width="1000"/>
</p>

