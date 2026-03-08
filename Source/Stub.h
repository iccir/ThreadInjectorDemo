#ifndef STUB_H
#define STUB_H

#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <pthread/pthread.h>

const uint64_t InjectFinishedSentinel = 0x21496E6A65637421;

typedef struct InjectData {
    int (*pcfmt)(
		pthread_t * __restrict,
		const pthread_attr_t *  __restrict,
		void * (*)(void * ),
		void * __restrict
    ); // pthread_create_from_mach_thread
    
    void *(*dlopen)(const char *, int);
    int (*pause)(void);

     // Function Pointer to InjectStubEntry1()
    void (*entry1)(struct InjectData *);
    
    // Filled with InjectFinishedSentinel when entry1 enters pause() loop
    uint64_t finished1;

    // Function Pointer to InjectStubEntry2()
    void (*entry2)(struct InjectData *);

    // Filled with InjectFinishedSentinel before entry2 returns
    uint64_t finished2;

    int pcfmtResult;
    void *dlopenResult;
    
    char payloadPath[1024];
} InjectData;

extern void InjectStubEntry(InjectData *d);

#endif /* STUB_H */
