#ifndef INJECTION_H
#define INJECTION_H

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
    InjectionLogLevelDefault, // Information about what the injector is doing
    InjectionLogLevelError    // Errors
} InjectionLogLevel;

typedef void (^InjectionLogCallback)(InjectionLogLevel level, const char *format, ...);

void InjectionSetLogCallback(InjectionLogCallback callback);

// Perform actual injection
bool InjectionInjectIntoProcess(
    pid_t pid,
    const char *fullPathToStub,
    const char *fullPathToPayload
);

#endif /* INJECTION_H */
