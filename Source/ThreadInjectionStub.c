#include "ThreadInjectionStub.h"
#include <dlfcn.h>
#include <ptrauth.h>

// This function is called on a thread created by thread_create...()
// We are very limited on what we can do here, as any calls to
// pthread APIs will explode.
//
void ThreadInjectionStubEntry1(ThreadInjectionData *d)
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


void ThreadInjectionStubEntry2(ThreadInjectionData *d)
{
    d->dlopenResult = d->dlopen(d->payloadPath, RTLD_NOW);
    d->finished2 = ThreadInjectionFinishedSentinel;
}
