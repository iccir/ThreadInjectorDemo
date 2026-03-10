#include <libproc.h>
#include <mach-o/dyld.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/proc_info.h>
#include <sys/ptrace.h>
#include <sys/sysctl.h>

#include "Injection.h"


static void sLog(FILE * f, char *format, ...)
{
    va_list v;
    va_start(v, format);
    
    vfprintf(f, format, v);
    fprintf(f, "\n");

    va_end(v);
}

#define sLogStdout(...) sLog(stdout, ##__VA_ARGS__)
#define sLogStderr(...) sLog(stderr, ##__VA_ARGS__)


bool sFindPidByName(const char *name, pid_t *outPid)
{
    bool  found  = false;
    pid_t result = 0;

    struct kinfo_proc *procs = NULL;

    int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0 };

    size_t procsSize = 0;
    if (sysctl(mib, 4, NULL, &procsSize, NULL, 0) < 0) {
        goto cleanup;
    }

    procs = malloc(procsSize);
    if (!procs) {
        goto cleanup;
    }

    if (sysctl(mib, 4, procs, &procsSize, NULL, 0) < 0) {
        goto cleanup;
    }

    size_t count = procsSize / sizeof(struct kinfo_proc);

    for (size_t i = 0; i < count; i++) {
        pid_t pid = procs[i].kp_proc.p_pid;
        if (pid <= 0) continue;

        char path[PROC_PIDPATHINFO_MAXSIZE];

        if (proc_pidpath(pid, path, sizeof(path)) > 0) {
            if (strstr(path, name)) {
                result = pid;
                found = true;
                break;
            }
        }
    }

    if (found) {
        *outPid = result;
    }

cleanup:
    free(procs);

    return found;
}


bool sFileExists(const char *path)
{
    struct stat st;
    if (stat(path, &st) != 0) return false;
    if (!S_ISREG(st.st_mode)) return false;
    
    return true;
}


bool sGetPid(const char *nameOrPid, pid_t *outPid)
{
    char *end;
    pid_t result = (pid_t)strtol(nameOrPid, &end, 10);

    if ((*end == 0) && (nameOrPid != end)) {
        *outPid = result;
        return true;

    } else {
        return sFindPidByName(nameOrPid, outPid);
    }
}


int main(int argc, char **argv, char **envp)
{
    InjectionSetLogCallback(^(InjectionLogLevel level, const char *format, ...) {
        va_list v;
        va_start(v, format);

        FILE *f = (level == InjectionLogLevelError) ? stderr : stdout;
        vfprintf(f, format, v);
        fprintf(f, "\n");

        va_end(v);
    });

    if (argc != 4) {
        sLogStderr("Usage: Injector path_to_stub path_to_payload pid_or_name");
        return 1;
    }

	char *stubPath    = argv[1];
    char *payloadPath = argv[2];
	char *pidOrName   = argv[3];

    pid_t pid;
    if (!sGetPid(pidOrName, &pid)) {
        sLogStderr("Could find process for '%s'", pidOrName);
        return 1;
    }
    
    if (!sFileExists(payloadPath)) {
        sLogStderr("Payload does not exist: '%s'", payloadPath);
        return 1;
    }
    
    if (!InjectionInjectIntoProcess(pid, stubPath, payloadPath)) {
        sLogStderr("Injection failed");
        return 2;
    } else {
        sLogStdout("Successfully injected into pid %ld", (long)pid);
    }
    
    return 0;
}
