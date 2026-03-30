#include "ThreadInjection.h"
#include "ThreadInjectionStub.h"

#include <dlfcn.h>
#include <mach/mach.h>
#include <ptrauth.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/param.h>

#include <mach-o/dyld_images.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>


#pragma mark - Logging

static ThreadInjectionLogCallback sLogCallback = NULL;

#define Log(...) __extension__({ \
    if (sLogCallback) sLogCallback(ThreadInjectionLogLevelDefault, ##__VA_ARGS__); \
})

#define LogError(...) __extension__({ \
    if (sLogCallback) sLogCallback(ThreadInjectionLogLevelError, ##__VA_ARGS__); \
})




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

    symtabBufferSize = symtab->nsyms * sizeof(struct nlist_64);
    vm_read(task, linkeditAddress + symtab->symoff, symtabBufferSize, (vm_offset_t *)&symtabBuffer, &symtabBufferSize);

    if (!symtabBuffer) {
        goto cleanup;
    }

    strtabBufferSize = symtab->strsize;
    vm_read(task, linkeditAddress + symtab->stroff, strtabBufferSize, (vm_offset_t *)&strtabBuffer, &strtabBufferSize);

    if (!strtabBuffer) {
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


static void *sGetRemoteSymbol(task_t task, const char *imageName, const char *symbolName)
{
    void *result = NULL;

    struct dyld_all_image_infos allImageInfos;
    struct dyld_image_info *images = NULL;

    if (!imageName || !symbolName) {
        goto cleanup;
    }

    // Get remote all_image_info_addr and store into allImageInfos
    {
        struct task_dyld_info dyldInfo;
        mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
        kern_return_t kr = task_info(task, TASK_DYLD_INFO, (task_info_t)&dyldInfo, &count);

        if (kr != KERN_SUCCESS) {
            LogError("sGetRemoteSymbol - task_info() failed %d", kr);
            goto cleanup;
        }

        if (!sRemoteRead(task, (vm_address_t)dyldInfo.all_image_info_addr, &allImageInfos, sizeof(allImageInfos))) {
            LogError("sGetRemoteSymbol - failed to read remote all_image_infos");
            goto cleanup;
        }
    }

    uint32_t imageCount = allImageInfos.infoArrayCount;
    if (imageCount == 0) {
        LogError("sGetRemoteSymbol - imageCount is 0");
        goto cleanup;
    }

    images = sRemoteAlloc(task, (vm_address_t)allImageInfos.infoArray, imageCount *sizeof(struct dyld_image_info));

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
    const char *fullPathToStub,
    const char *fullPathToPayload
) {
    bool ok = false;

    kern_return_t kr;

    thread_act_t thread = 0;
    mach_port_t task = 0;

    ThreadInjectionData *localData = alloca(sizeof(ThreadInjectionData));

    mach_vm_address_t localStub = 0;
    mach_vm_size_t localStubSize = 0;
    void *localStubEntry1 = NULL;
    void *localStubEntry2 = NULL;

    mach_vm_address_t remoteStub = 0;

    mach_vm_address_t remoteStack = 0;
    vm_size_t remoteStackSize = 16 * 1024;

    mach_vm_address_t remoteData = 0;
    vm_size_t remoteDataSize = sizeof(ThreadInjectionData);

    strncpy(localData->payloadPath, fullPathToPayload, sizeof(localData->payloadPath));

    // Start with task_for_pid() before loading anything
    {
        kr = task_for_pid(mach_task_self(), pid, &task);
        if (kr != KERN_SUCCESS) {
            LogError("task_for_pid(%d) failed: %d\n", pid, kr);
            goto cleanup;
        }
    }

    // Load stub dylib into current process, find our two entry functions
    {
        dlopen(fullPathToStub, RTLD_NOW);

        localStubEntry1 = dlsym(RTLD_DEFAULT, "ThreadInjectionStubEntry1");
        localStubEntry2 = dlsym(RTLD_DEFAULT, "ThreadInjectionStubEntry2");

        if (!localStubEntry1 || !localStubEntry2) {
            LogError("Could not load stub bundle.\n");
            goto cleanup;
        }
    }

    // Use dladdr() to find the starting address of our loaded dylib
    {
        Dl_info dlInfo;
        dladdr(localStubEntry1, &dlInfo);

        localStub = (mach_vm_address_t)dlInfo.dli_fbase;
    }

    // Use mach_vm_region() to fill localStubSize
    {
        mach_port_t objectName;

        struct vm_region_basic_info_64 info;
        mach_msg_type_number_t infoCount = VM_REGION_BASIC_INFO_COUNT_64;

        kr = mach_vm_region(mach_task_self(), &localStub, &localStubSize, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info, &infoCount, &objectName);
        if (kr != KERN_SUCCESS) {
            LogError("mach_vm_region() returned %d\n", kr);
            goto cleanup;
        }
        
        // Round up to page boundary
        localStubSize = round_page(localStubSize);
    }
        
    // Lookup remote symbol locations using CoreSymbolication
    {
       
        {
            uint64_t startTime = mach_absolute_time();

             mach_timebase_info_data_t timebase;
                mach_timebase_info(&timebase);

            localData->pcfmt  = sGetRemoteSymbol(task, "libsystem_pthread.dylib", "_pthread_create_from_mach_thread");
            localData->dlopen = sGetRemoteSymbol(task, "libdyld.dylib", "_dlopen");
            localData->pause  = sGetRemoteSymbol(task, "libsystem_c.dylib", "_pause");

            uint64_t elapsed = (mach_absolute_time() - startTime) * timebase.numer / timebase.denom;
            printf("raw elapsed: %ldms\n", (long)(elapsed / 1000000));
        }

    }

    // Map remote stub using mach_vm_remap(), this should preserve code signatures
    {
        vm_prot_t currentProtection;
        vm_prot_t maxProtection;

        kr = mach_vm_remap(
            task,
            &remoteStub, localStubSize,
            0, VM_FLAGS_ANYWHERE|VM_FLAGS_RETURN_DATA_ADDR,
            mach_task_self(), localStub, false,
            &currentProtection, &maxProtection, VM_INHERIT_NONE
        );
        if (kr != KERN_SUCCESS) {
            LogError("Stub - mach_vm_remap() failed: %d\n", kr);
            goto cleanup;
        }

        kr = vm_protect(task, remoteStub, localStubSize, 1, VM_PROT_READ | VM_PROT_EXECUTE);
        if (kr != KERN_SUCCESS) {
            LogError("Stub - vm_protect() failed: %d\n", kr);
            goto cleanup;
        }
    }

    // Now that we have remoteStub, we can fill entry1 and entry2 using some pointer math
    {
        localStubEntry1 = ptrauth_strip(localStubEntry1, ptrauth_key_function_pointer);
        localStubEntry2 = ptrauth_strip(localStubEntry2, ptrauth_key_function_pointer);

        localData->entry1 = remoteStub + (localStubEntry1 - localStub);
        localData->entry2 = remoteStub + (localStubEntry2 - localStub);
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
    kr = thread_create(task, &thread);
    if (kr != KERN_SUCCESS) {
        LogError("thread_create() failed: %d\n", kr);
        goto cleanup;
    }
    
    // Right now, localThreadState's pc and sp are signed with local PAC keys.
    // We need to resign them using the target's PAC keys.
    // thread_convert_thread_state() handles this for us.
    //
    kr = thread_convert_thread_state(
        thread, THREAD_CONVERT_THREAD_STATE_FROM_SELF, threadFlavor,
        (thread_state_t) &localThreadState,   localThreadFlavorCount,
        (thread_state_t) &remoteThreadState, &remoteThreadFlavorCount
    );
    if (kr != KERN_SUCCESS) {
        LogError("thread_convert_thread_state() failed: %d\n", kr);
        goto cleanup;
    }
    
    // Terminate the dummy thread
    kr = thread_terminate(thread);
    if (kr != KERN_SUCCESS) {
        LogError("thread_terminate() failed: %d\n", kr);
        goto cleanup;
    }
    
    // Now make the real thread with thread_create_running()
    kr = thread_create_running(
        task, threadFlavor,
        (thread_state_t)&remoteThreadState, remoteThreadFlavorCount,
        &thread
    );
    if (kr != KERN_SUCCESS) {
        LogError("thread_create_running() failed: %d\n", kr);
        goto cleanup;
    }
    
    // InjectStubEntry1() and InjectStubEntry2() should now be executing in
    // the target. Wait for finished1 and finished2 to have our magic value.
    //
    while (1) {
        vm_size_t localDataSize = sizeof(ThreadInjectionData);

        kr = vm_read_overwrite(task, remoteData, sizeof(ThreadInjectionData), (vm_address_t)localData, &localDataSize);
        if (kr != KERN_SUCCESS) {
            LogError("Data - vm_read_overwrite() failed: %d\n", kr);
            goto cleanup;
        }

        uint64_t finished1 = localData->finished1;
        uint64_t finished2 = localData->finished2;

        if (
            finished1 == ThreadInjectionFinishedSentinel &&
            finished2 == ThreadInjectionFinishedSentinel
        ) {
            break;
        }

        /*
            Right now, we loop forever as long as vm_read_overwrite() doesn't fail.
            In practice, there should probably be a timeout check here:
            
            if (timedOut) {
                LogError("Timed out while waiting for sentinels");
                goto cleanup;
            }
        */

        usleep(10000);
    }

    ok = true;
    
cleanup:
    if (thread) {
        thread_terminate(thread);
    }

    if (remoteStack) {
        vm_deallocate(task, remoteStack, remoteStackSize);
    }
    
    if (remoteData) {
        vm_deallocate(task, remoteData, sizeof(ThreadInjectionData));
    }
    
    return ok;
}

