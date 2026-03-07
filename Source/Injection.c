#include "Injection.h"
#include "Stub.h"

#include <mach/mach.h>
#include <dlfcn.h>
#include <stdio.h>
#include <pthread/pthread_spis.h>
#include <stdlib.h>
#include <ptrauth.h>
#include <unistd.h>

#pragma mark - CoreSymbolication Privates

typedef struct {
	void *unknown1;
	void *unknown2;
} CSTypeRef;

typedef struct  {
   void *location;
   uint64_t length;
} CSRange;

typedef CSTypeRef CSSymbolRef;
typedef CSTypeRef CSSymbolicatorRef;

extern CSSymbolicatorRef CSSymbolicatorCreateWithPid(pid_t pid);
extern CSSymbolRef CSSymbolicatorGetSymbolWithNameAtTime(CSSymbolicatorRef cs, const char* name, uint64_t time);
extern CSRange CSSymbolGetRange(CSSymbolRef symbol);
extern void CSRelease(CSTypeRef type);


#pragma mark - Logging

static InjectionLogCallback sLogCallback = NULL;

#define Log(...) __extension__({ \
    if (sLogCallback) sLogCallback(InjectionLogLevelDefault, ##__VA_ARGS__); \
})

#define LogError(...) __extension__({ \
    if (sLogCallback) sLogCallback(InjectionLogLevelError, ##__VA_ARGS__); \
})


#pragma mark - Private Functions

static void *sGetRemoteSymbol(CSSymbolicatorRef symbolicator, const char *name)
{
    CSSymbolRef symbol = CSSymbolicatorGetSymbolWithNameAtTime(symbolicator, name, 0);
    CSRange range = CSSymbolGetRange(symbol);
   
    return range.location;
}


static void *sGetRemoteStubFunction(void *remoteStub, void *localStub, void *localStubFunction)
{
    localStubFunction = ptrauth_strip(localStubFunction, ptrauth_key_function_pointer);
    return remoteStub + (localStubFunction - localStub);
}


#pragma mark - Public Functions

void InjectionSetLogCallback(InjectionLogCallback callback)
{
    sLogCallback = callback;
}


bool InjectionInjectIntoProcess(
    pid_t pid,
    const char *fullPathToStub,
    const char *fullPathToPayload
) {
    bool ok = false;

    kern_return_t kr;

    thread_act_t thread = 0;
    mach_port_t task = 0;

    InjectData *localData = alloca(sizeof(InjectData));

    mach_vm_address_t localStub = 0;
    mach_vm_size_t localStubSize = 0;
    void *localStubEntry1 = NULL;
    void *localStubEntry2 = NULL;

    mach_vm_address_t remoteStub = 0;

    mach_vm_address_t remoteStack = 0;
    vm_size_t remoteStackSize = 16 * 1024;

    mach_vm_address_t remoteData = 0;
    vm_size_t remoteDataSize = sizeof(InjectData);

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

        localStubEntry1 = dlsym(RTLD_DEFAULT, "InjectStubEntry1");
        localStubEntry2 = dlsym(RTLD_DEFAULT, "InjectStubEntry2");

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
        CSSymbolicatorRef symbolicator = CSSymbolicatorCreateWithPid(pid);
    
        localData->pcfmt  = sGetRemoteSymbol(symbolicator, "pthread_create_from_mach_thread");
        localData->dlopen = sGetRemoteSymbol(symbolicator, "dlopen");
        localData->pause  = sGetRemoteSymbol(symbolicator, "pause");

        CSRelease(symbolicator);
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
        localData->entry1 = sGetRemoteStubFunction((void *)remoteStub, (void *)localStub, localStubEntry1);
        localData->entry2 = sGetRemoteStubFunction((void *)remoteStub, (void *)localStub, localStubEntry2);
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

        kr = vm_write(task, remoteData, (vm_offset_t)localData, sizeof(InjectData));
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
        vm_size_t localDataSize = sizeof(InjectData);

        kr = vm_read_overwrite(task, remoteData, sizeof(InjectData), (vm_address_t)localData, &localDataSize);
        if (kr != KERN_SUCCESS) {
            LogError("Data - vm_read_overwrite() failed: %d\n", kr);
            goto cleanup;
        }

        uint64_t finished1 = localData->finished1;
        uint64_t finished2 = localData->finished2;

        if (finished1 == InjectFinishedSentinel && finished2 == InjectFinishedSentinel) {
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
        vm_deallocate(task, remoteData, sizeof(InjectData));
    }
    
    return ok;
}

