#ifndef THREAD_INJECTION_H
#define THREAD_INJECTION_H

#include <sys/types.h>
#include <stdbool.h>

// Logging is a complicated mess on macOS.
//
// Although os_log() is suppose to be the preferred solution, it lacks basic
// functionality like va_list support or redirection to stdout/stderr.
//
// Hence, everybody writes their own wrappers.
//
typedef enum {
    ThreadInjectionLogLevelDefault, // Information about what the injector is doing
    ThreadInjectionLogLevelError    // Errors
} ThreadInjectionLogLevel;

typedef void (^ThreadInjectionLogCallback)(ThreadInjectionLogLevel level, const char *format, ...);

void ThreadInjectionSetLogCallback(ThreadInjectionLogCallback callback);

// Perform actual injection
bool ThreadInjectionInject(
    pid_t pid,
    const char *fullPathToPayload
);

#endif /* THREAD_INJECTION_H */
