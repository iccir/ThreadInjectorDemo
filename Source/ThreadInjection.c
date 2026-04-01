#include "ThreadInjection.h"

#include <dlfcn.h>
#include <mach/mach.h>
#include <ptrauth.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/param.h>

#include <mach-o/dyld_images.h>
#include <mach-o/ldsyms.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <mach-o/getsect.h>


#pragma mark - Logging

static ThreadInjectionLogCallback sLogCallback = NULL;

#define Log(...) __extension__({ \
    if (sLogCallback) sLogCallback(ThreadInjectionLogLevelDefault, ##__VA_ARGS__); \
})

#define LogError(...) __extension__({ \
    if (sLogCallback) sLogCallback(ThreadInjectionLogLevelError, ##__VA_ARGS__); \
})


#pragma mark - Entry Functions

typedef struct ThreadInjectionData {
    int (*pcfmt)(
		pthread_t * __restrict,
		const pthread_attr_t *  __restrict,
		void * (*)(void * ),
		void * __restrict
    ); // pthread_create_from_mach_thread
    
    void *(*dlopen)(const char *, int);
    int (*pause)(void);

     // Function Pointer to ThreadInjectionEntry1()
    void (*entry1)(struct ThreadInjectionData *);
    
    // Filled with ThreadInjectionFinishedSentinel before entry1 enters pause() loop
    uint64_t finished1;

    // Function Pointer to ThreadInjectionEntry2()
    void (*entry2)(struct ThreadInjectionData *);

    // Filled with ThreadInjectionFinishedSentinel before entry2 returns
    uint64_t finished2;

    int pcfmtResult;
    void *dlopenResult;
    
    char payloadPath[PATH_MAX];
} ThreadInjectionData;


#define ThreadInjectionFinishedSentinel 0x21496E6A65637421
#define ThreadInjectionSectionName "__threadinject"

// Note:
//
// ThreadInjectionEntry1 and ThreadInjectionEntry2 will be copied into the remote process
// via mach_vm_remap(). We need to round 'src_address' and 'size' towards page boundaries,
// otherwise mach_vm_remap() will fail.
//
// As a result, we may copy additional portions of the __TEXT segment into the target process.
// While unlikely to be an issue, this theoretically could expose sensitive information.
//
// As a nicety, we use the aligned(0x4000) attribute in an attempt to get the following layout:
//
// * ThreadInjectionEntry1 (on a page boundary)
// * ThreadInjectionEntry2
// * Padding with 'nop' instruction
// * ThreadInjectionEntryEnd (on a page boundary)
//
// Assuming that the linker doesn't reorder ThreadInjectionEntry1/2/End,
// we can then mach_vm_remap() with a 'src_address' of &ThreadInjectionEntry1 and
// a 'size' of (ThreadInjectionEntryEnd - ThreadInjectionEntry1).
//
// If re-ordering occurs, we use getsectiondata() as a fallback.


// This function is called on a thread created by thread_create...()
// We are very limited on what we can do here, as any calls to
// pthread APIs will explode.
//
// We place this function in the "__TEXT,__threadinject" section so that it can
// be easily mach_vm_remap'd to the remote process.
//
__attribute__((section(SEG_TEXT "," ThreadInjectionSectionName), aligned(0x4000)))
void ThreadInjectionEntry1(ThreadInjectionData *d)
{
    // ptrauth_sign_unauthenticated() compiles into a PACIA instruction and is ok to use.
    d->pcfmt  = ptrauth_sign_unauthenticated(d->pcfmt,  ptrauth_key_function_pointer, 0);
    d->dlopen = ptrauth_sign_unauthenticated(d->dlopen, ptrauth_key_function_pointer, 0);
    d->pause  = ptrauth_sign_unauthenticated(d->pause,  ptrauth_key_function_pointer, 0);
    d->entry1 = ptrauth_sign_unauthenticated(d->entry1, ptrauth_key_function_pointer, 0);
    d->entry2 = ptrauth_sign_unauthenticated(d->entry2, ptrauth_key_function_pointer, 0);

    pthread_t entry2Thread;

    d->pcfmtResult = d->pcfmt(&entry2Thread, NULL, (void *)d->entry2, d);
    d->finished1 = ThreadInjectionFinishedSentinel;
    
    while (1) {
        d->pause();
    }
}


__attribute__((section(SEG_TEXT "," ThreadInjectionSectionName)))
void ThreadInjectionEntry2(ThreadInjectionData *d)
{
    d->dlopenResult = d->dlopen(d->payloadPath, RTLD_NOW);
    d->finished2 = ThreadInjectionFinishedSentinel;
}


// See above note - this function exists solely to influence padding
__attribute__((section(SEG_TEXT "," ThreadInjectionSectionName), aligned(0x4000), used))
void ThreadInjectionEntryEnd(void) { }


#pragma mark - Remote Reading

static bool sRemoteRead(task_t task, vm_address_t address, void *buffer, vm_size_t inSize)
{
    vm_size_t outSize = 0;
    kern_return_t kr = vm_read_overwrite(task, address, inSize, (vm_address_t)buffer, &outSize);
    return (kr == KERN_SUCCESS) && (outSize == inSize);
};


static void *sRemoteAlloc(task_t task, vm_address_t addr, vm_size_t inSize)
{
    void *buffer = malloc(inSize);
    
    if (sRemoteRead(task, addr, buffer, inSize)) {
        return buffer;
    } else {
        free(buffer);
        return NULL;
    }
}


static bool sRemoteReadString(task_t task, vm_address_t address, char *buffer, vm_size_t inSize)
{
    bool ok = sRemoteRead(task, address, buffer, inSize);

    if (!ok) {
        // Slow path in the very rare case that address is near the end of a vm region.
        // Read the bytes individually.
        //
        for (size_t i = 0; i < inSize; i++) {
            ok = sRemoteRead(task, address + i, buffer + i, 1);
            if (!ok || !buffer[i]) break;
        }
    }
    
    if (inSize) {
        buffer[inSize - 1] = 0;
    }

    return ok;
}


static vm_address_t sRemoteWalkSymbolTable(task_t task, vm_address_t loadAddress, const char *symbolName)
{
    vm_address_t result = 0;

    uint8_t *loadCommands = NULL;

    mach_msg_type_number_t symtabBufferSize = 0;
    struct nlist_64 *symtabBuffer = NULL;

    mach_msg_type_number_t strtabBufferSize = 0;
    const char *strtabBuffer = NULL;

    struct mach_header_64 machHeader;
    if (
        !sRemoteRead(task, loadAddress, &machHeader, sizeof(machHeader)) ||
        machHeader.magic != MH_MAGIC_64
    ) {
        goto cleanup;
    }

    loadCommands = sRemoteAlloc(task, loadAddress + sizeof(machHeader), machHeader.sizeofcmds);
    if (!loadCommands) {
        goto cleanup;
    }
    
    struct segment_command_64 *text     = NULL;
    struct segment_command_64 *linkedit = NULL;
    struct symtab_command     *symtab   = NULL;

    struct load_command *loadCommand     = (struct load_command *)loadCommands;
    struct load_command *loadCommandsEnd = (struct load_command *)(loadCommands + machHeader.sizeofcmds);

    for (size_t i = 0; i < machHeader.ncmds && (loadCommand < loadCommandsEnd); i++) {
        if (
            loadCommand->cmdsize < sizeof(struct load_command) ||
            (uint8_t *)loadCommand + loadCommand->cmdsize > (uint8_t *)loadCommandsEnd
        ) {
            goto cleanup;
        }

        if (loadCommand->cmd == LC_SEGMENT_64) {
            struct segment_command_64 *seg = (struct segment_command_64 *)loadCommand;

            if (!text && strncmp(seg->segname, SEG_TEXT, sizeof(seg->segname)) == 0) {
                text = seg;
            } else if (!linkedit && strncmp(seg->segname, SEG_LINKEDIT, sizeof(seg->segname)) == 0) {
                linkedit = seg;
            }

        } else if (loadCommand->cmd == LC_SYMTAB) {
            symtab = (struct symtab_command *)loadCommand;
        }

        loadCommand = (struct load_command *)((uint8_t *)loadCommand + loadCommand->cmdsize);
    }

    if (!text || !linkedit || !symtab || symtab->nsyms == 0) {
        goto cleanup;
    }

    int64_t slide = (int64_t)loadAddress - (int64_t)text->vmaddr;

    vm_address_t linkeditAddress = (vm_address_t)((linkedit->vmaddr + slide) - linkedit->fileoff);

    mach_msg_type_number_t bytesRead = 0;
    kern_return_t kr;

    symtabBufferSize = symtab->nsyms * sizeof(struct nlist_64);
    kr = vm_read(task, linkeditAddress + symtab->symoff, symtabBufferSize, (vm_offset_t *)&symtabBuffer, &bytesRead);

    if (!symtabBuffer || (kr != KERN_SUCCESS) || (bytesRead != symtabBufferSize)) {
        goto cleanup;
    }

    strtabBufferSize = symtab->strsize;
    kr = vm_read(task, linkeditAddress + symtab->stroff, strtabBufferSize, (vm_offset_t *)&strtabBuffer, &bytesRead);

    if (!strtabBuffer || (kr != KERN_SUCCESS) || (bytesRead != strtabBufferSize)) {
        goto cleanup;
    }

    for (size_t i = 0; i < symtab->nsyms; i++) {
        uint32_t strx = symtabBuffer[i].n_un.n_strx;
        if (strx >= symtab->strsize) continue;

        if (strcmp(symbolName, strtabBuffer + strx) == 0) {
            result = (vm_address_t)(symtabBuffer[i].n_value + (uint64_t)slide);
            break;
        }
    }

cleanup:
    if (loadCommands) free(loadCommands);
    if (symtabBuffer) vm_deallocate(mach_task_self(), (vm_address_t)symtabBuffer, symtabBufferSize);
    if (strtabBuffer) vm_deallocate(mach_task_self(), (vm_address_t)strtabBuffer, strtabBufferSize);

    return result;
}


static bool sGetAllImageInfos(task_t task, struct dyld_all_image_infos *outAllImageInfos)
{
    struct task_dyld_info dyldInfo;
    mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
    kern_return_t kr = task_info(task, TASK_DYLD_INFO, (task_info_t)&dyldInfo, &count);

    if (kr != KERN_SUCCESS) {
        LogError("sGetRemoteSymbol - task_info() failed %d", kr);
        return false;
    }

    if (!sRemoteRead(task, (vm_address_t)dyldInfo.all_image_info_addr, outAllImageInfos, sizeof(*outAllImageInfos))) {
        LogError("sGetRemoteSymbol - failed to read remote all_image_infos");
        return false;
    }
    
    return true;
}


static void *sGetRemoteSymbol(task_t task, const char *imageName, const char *symbolName)
{
    void *result = NULL;

    struct dyld_all_image_infos allImageInfos;
    struct dyld_image_info *images = NULL;

    if (!imageName || !symbolName) {
        goto cleanup;
    }

    if (!sGetAllImageInfos(task, &allImageInfos)) {
        goto cleanup;
    }

    uint32_t imageCount = allImageInfos.infoArrayCount;
    if (imageCount == 0) {
        LogError("sGetRemoteSymbol - imageCount is 0");
        goto cleanup;
    }

    images = sRemoteAlloc(task, (vm_address_t)allImageInfos.infoArray, imageCount *sizeof(struct dyld_image_info));
    if (!images) {
        LogError("sGetRemoteSymbol - images is NULL");
        goto cleanup;
    }

    for (size_t i = 0; i < imageCount && result == 0; i++) {
        char path[PATH_MAX];
        if (!sRemoteReadString(task, (vm_address_t)images[i].imageFilePath, path, PATH_MAX)) {
            continue;
        }
        
        path[PATH_MAX - 1] = 0;
        
        if (!strstr(path, imageName)) {
            continue;
        }

        vm_address_t loadAddress = (vm_address_t)images[i].imageLoadAddress;
        result = (void *)sRemoteWalkSymbolTable(task, loadAddress, symbolName);
        if (result) break;
    }

cleanup:
    free(images);

    return result;
}


#pragma mark - Public Functions

void ThreadInjectionSetLogCallback(ThreadInjectionLogCallback callback)
{
    sLogCallback = callback;
}


bool ThreadInjectionInject(
    pid_t pid,
    const char *fullPathToPayload
) {
    bool ok = false;

    kern_return_t kr;

    thread_act_t dummyThread = 0;
    thread_act_t remoteThread = 0;
    mach_port_t task = 0;
    
    // When true, we cannot safely deallocate remoteThread / remoteStack / remoteData
    bool entry1IsCritical = false;
    bool entry2IsCritical = false;

    ThreadInjectionData *localData = alloca(sizeof(ThreadInjectionData));

    vm_address_t  localSection = 0;
    unsigned long localSectionSize = 0;

    uintptr_t localEntry1   = (uintptr_t)ptrauth_strip(&ThreadInjectionEntry1,   ptrauth_key_function_pointer);
    uintptr_t localEntry2   = (uintptr_t)ptrauth_strip(&ThreadInjectionEntry2,   ptrauth_key_function_pointer);
    uintptr_t localEntryEnd = (uintptr_t)ptrauth_strip(&ThreadInjectionEntryEnd, ptrauth_key_function_pointer);

    mach_vm_address_t remoteSection = 0;

    mach_vm_address_t remoteStack = 0;
    vm_size_t remoteStackSize = 16 * 1024;

    mach_vm_address_t remoteData = 0;
    vm_size_t remoteDataSize = sizeof(ThreadInjectionData);

    strlcpy(localData->payloadPath, fullPathToPayload, sizeof(localData->payloadPath));

    // Start with task_for_pid() before loading anything
    {
        kr = task_for_pid(mach_task_self(), pid, &task);
        if (kr != KERN_SUCCESS) {
            LogError("task_for_pid(%d) failed: %d\n", pid, kr);
            goto cleanup;
        }
    }

    // Wait until remote process has libSystemInitialized=true
    {
        bool isLibSystemInitialized = false;

        for (size_t loopGuard = 0; loopGuard < 100; loopGuard++) {
            struct dyld_all_image_infos allImageInfos;
            
            if (!sGetAllImageInfos(task, &allImageInfos)) {
                LogError("sGetAllImageInfos() failed");
                goto cleanup;
            }

            isLibSystemInitialized = allImageInfos.libSystemInitialized;
            if (isLibSystemInitialized) break;

            usleep(1000); // Delay 1ms
        }
        
        if (!isLibSystemInitialized) {
            LogError("Timed out while waiting for libSystemInitialized=true in pid %ld", pid);
            goto cleanup;
        }
    }

    // Map entry functions into remote process using mach_vm_remap(), this should preserve code signatures
    {
        vm_prot_t currentProtection;
        vm_prot_t maxProtection;

        // Assuming the our functions have been correctly aligned and not reordered,
        // we can directly use localEntry1 and (localEntryEnd - localEntry1)
        if (
            (localEntry1 < localEntry2)    && (localEntry2 < localEntryEnd) &&
            (localEntry1 % PAGE_SIZE == 0) && (localEntryEnd % PAGE_SIZE == 0)
        ) {
            localSection     = localEntry1;
            localSectionSize = localEntryEnd - localEntry1;

        // Fallback: use getsectiondata() and expand to page boundaries.
        } else {
            unsigned long unroundedSize;
            vm_address_t unroundedStart = (vm_address_t) getsectiondata(
                &_mh_execute_header,
                SEG_TEXT, ThreadInjectionSectionName,
                &unroundedSize
            );

            // Calculate start/end/size by rounding to page boundaries (needed for mach_vm_remap)
            vm_address_t roundedStart = trunc_page(unroundedStart);
            vm_address_t roundedEnd   = round_page(unroundedStart + unroundedSize);

            localSection     = roundedStart;
            localSectionSize = roundedEnd - roundedStart;
        }

        kr = mach_vm_remap(
            task,
            &remoteSection, localSectionSize,
            0, VM_FLAGS_ANYWHERE | VM_FLAGS_RETURN_DATA_ADDR,
            mach_task_self(), (mach_vm_address_t)localSection, false,
            &currentProtection, &maxProtection, VM_INHERIT_NONE
        );
        if (kr != KERN_SUCCESS) {
            LogError("Entry Functions - mach_vm_remap() failed: %d\n", kr);
            goto cleanup;
        }

        kr = vm_protect(task, remoteSection, localSectionSize, 1, VM_PROT_READ | VM_PROT_EXECUTE);
        if (kr != KERN_SUCCESS) {
            LogError("Entry Functions - vm_protect() failed: %d\n", kr);
            goto cleanup;
        }
    }

    // Now that we have remoteSection, we can fill entry1 and entry2 using some pointer math
    {
        localData->entry1 = (void *)(remoteSection + (localEntry1 - localSection));
        localData->entry2 = (void *)(remoteSection + (localEntry2 - localSection));
    }

    // Lookup remote symbol locations
    {
        localData->pcfmt  = sGetRemoteSymbol(task, "libsystem_pthread.dylib", "_pthread_create_from_mach_thread");
        localData->dlopen = sGetRemoteSymbol(task, "libdyld.dylib", "_dlopen");
        localData->pause  = sGetRemoteSymbol(task, "libsystem_c.dylib", "_pause");
    }

    // Allocate and protect remote data, then copy localData -> remoteData
    {
        kr = mach_vm_allocate(task, &remoteData, remoteDataSize, VM_FLAGS_ANYWHERE);
        if (kr != KERN_SUCCESS) {
            LogError("Data - mach_vm_allocate() failed: %d\n", kr);
            goto cleanup;
        }

        kr = vm_protect(task, remoteData, remoteDataSize, 1, VM_PROT_READ | VM_PROT_WRITE);
        if (kr != KERN_SUCCESS) {
            LogError("Data - vm_protect() failed: %d\n", kr);
            goto cleanup;
        }

        kr = vm_write(task, remoteData, (vm_offset_t)localData, sizeof(ThreadInjectionData));
        if (kr != KERN_SUCCESS) {
            LogError("Data - vm_write() failed: %d\n", kr);
            goto cleanup;
        }
    }

    // Allocate and protect remote stack
    {
        kr = mach_vm_allocate(task, &remoteStack, remoteStackSize, VM_FLAGS_ANYWHERE);
        if (kr != KERN_SUCCESS) {
            LogError("Stack - mach_vm_allocate() failed: %d\n", kr);
            goto cleanup;
        }

        kr = vm_protect(task, remoteStack, remoteStackSize, 1, VM_PROT_READ | VM_PROT_WRITE);
        if (kr != KERN_SUCCESS) {
            LogError("Stack - vm_protect() failed: %d\n", kr);
            goto cleanup;
        }
    }

    arm_thread_state64_t localThreadState = { 0 };
    arm_thread_state64_t remoteThreadState = { 0 };
    thread_state_flavor_t threadFlavor = ARM_THREAD_STATE64;
    mach_msg_type_number_t localThreadFlavorCount = ARM_THREAD_STATE64_COUNT;
    mach_msg_type_number_t remoteThreadFlavorCount = ARM_THREAD_STATE64_COUNT;

    // programCounter needs to be signed with ptrauth_key_function_pointer before
    // we can pass it into __darwin_arm_thread_state64_set_pc_fptr()
    //
    void *programCounter = ptrauth_sign_unauthenticated(localData->entry1, ptrauth_key_function_pointer, 0);

    // Note: stackPointer needs to be 16-byte aligned per ABI.
    // Stack grows downward, so set to end of our allocated space
    //
    void *stackPointer = (void *)(remoteStack + remoteStackSize);

    // x0 is the first argument
    localThreadState.__x[0] = remoteData;
    
    __darwin_arm_thread_state64_set_pc_fptr(localThreadState, programCounter);
    __darwin_arm_thread_state64_set_sp(localThreadState, stackPointer);
    
    // Create a dummy thread to use with thread_convert_thread_state()
    kr = thread_create(task, &dummyThread);
    if (kr != KERN_SUCCESS) {
        LogError("thread_create() failed: %d\n", kr);
        goto cleanup;
    }
    
    // Right now, localThreadState's pc and sp are signed with local PAC keys.
    // We need to resign them using the target's PAC keys.
    // thread_convert_thread_state() handles this for us.
    //
    kr = thread_convert_thread_state(
        dummyThread, THREAD_CONVERT_THREAD_STATE_FROM_SELF, threadFlavor,
        (thread_state_t) &localThreadState,   localThreadFlavorCount,
        (thread_state_t) &remoteThreadState, &remoteThreadFlavorCount
    );
    if (kr != KERN_SUCCESS) {
        LogError("thread_convert_thread_state() failed: %d\n", kr);
        goto cleanup;
    }
    
    // Terminate the dummy thread
    kr = thread_terminate(dummyThread);
    dummyThread = 0;
    if (kr != KERN_SUCCESS) {
        LogError("thread_terminate() failed: %d\n", kr);
        goto cleanup;
    }
    
    // Now make the real thread with thread_create_running()
    kr = thread_create_running(
        task, threadFlavor,
        (thread_state_t)&remoteThreadState, remoteThreadFlavorCount,
        &remoteThread
    );
    if (kr != KERN_SUCCESS) {
        LogError("thread_create_running() failed: %d\n", kr);
        goto cleanup;
    }

    // At this point, it is now unsafe to cleanup various remote* variables
    {
        entry1IsCritical = true;
        entry2IsCritical = true;
    }
    
    // ThreadInjectionEntry1() and ThreadInjectionEntry2() should now be executing in
    // the target. Wait for finished1 and finished2 to have our sentinel value.
    //
    for (size_t loopGuard = 0; loopGuard < 250; loopGuard++) {
        vm_size_t localDataSize = sizeof(ThreadInjectionData);

        kr = vm_read_overwrite(task, remoteData, sizeof(ThreadInjectionData), (vm_address_t)localData, &localDataSize);
        if (kr != KERN_SUCCESS) {
            LogError("Data - vm_read_overwrite() failed: %d\n", kr);
            goto cleanup;
        }

        uint64_t finished1 = localData->finished1;
        uint64_t finished2 = localData->finished2;

        if (finished1) entry1IsCritical = false;
        if (finished2) entry2IsCritical = false;

        if (
            finished1 == ThreadInjectionFinishedSentinel &&
            finished2 == ThreadInjectionFinishedSentinel
        ) {
            ok = true;
            break;
        }

        usleep(1000); // Delay 1ms
    }
   
cleanup:
    if (dummyThread) {
        thread_terminate(dummyThread);
    }

    if (remoteThread && !entry1IsCritical) {
        if (thread_terminate(remoteThread) == KERN_SUCCESS) {
            remoteThread = 0;
        } else {
            LogError("thread_terminate() of remoteThread failed");
        }
    }

    if (remoteStack) {
        if (!remoteThread) {
            if (vm_deallocate(task, remoteStack, remoteStackSize) != KERN_SUCCESS) {
                LogError("vm_dealloc() of remoteStack failed");
                ok = false;
            }

        } else {
            LogError("Cannot cleanup remoteStack due to remoteThread still running");
        }
    }
    
    if (remoteData) {
        if (!entry1IsCritical && !entry2IsCritical) {
            if (vm_deallocate(task, remoteData, sizeof(ThreadInjectionData)) != KERN_SUCCESS) {
                LogError("vm_dealloc() of remoteData failed");
                ok = false;
            }

        } else {
            LogError("Cannot cleanup remoteData due to critical sections: %ld %ld", entry1IsCritical, entry2IsCritical);
        }
    }
    
    if (task) {
        mach_port_deallocate(mach_task_self(), task);
    }
    
    return ok;
}

