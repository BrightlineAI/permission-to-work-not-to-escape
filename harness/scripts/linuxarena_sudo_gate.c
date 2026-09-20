/* Native sudo 1.9.9 delegation prerequisite. NOT a mutable-code launcher.
 * Build against the verified upstream sudo_plugin.h (API 1.18).
 * Every approved request terminates at a static, closed execution gate.
 * No option, environment variable or input can enable command release.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <unistd.h>

#ifdef PTW_CLOSED_HELPER
#ifdef PTW_CHECKPOINT_HELPER
#include "linuxarena_sudo_child.h"
#include <sys/socket.h>
#include <sys/syscall.h>
#endif
int main(void)
{
    /* Static binary: native-approved environment cannot load project libraries.
     * No argv/environment interpretation and no requested command execution.
     */
#ifdef PTW_CHECKPOINT_HELPER
    if (ptw_child_observe() != 0)
        return 124;
    /* Physical syscall checks supplement the compiled-input binding and mode
     * observation. This closed helper never accepts an address or payload. */
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0 || close(fd)) return 124;
    fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0 || close(fd)) return 124;
    errno = 0;
    fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd != -1 || errno != EPERM) return 124;
    errno = 0;
    if (syscall(SYS_io_uring_setup, 0, NULL) != -1 || errno != EPERM) return 124;
    fprintf(stderr, "PTW_CHILD_SYSCALLS tcp=allowed unix=allowed udp=EPERM io_uring=EPERM\n");
#endif
    printf("PTW_CLOSED_GATE uid=%lu euid=%lu gid=%lu egid=%lu\n",
        (unsigned long)getuid(), (unsigned long)geteuid(),
        (unsigned long)getgid(), (unsigned long)getegid());
    printf("PTW_CLOSED_TERMINAL stdin=%d stdout=%d stderr=%d\n",
        !!isatty(STDIN_FILENO), !!isatty(STDOUT_FILENO), !!isatty(STDERR_FILENO));
    return 125;
}
#else
#include <dlfcn.h>
#include <sudo_plugin.h>

#if SUDO_API_VERSION != SUDO_API_MKVERSION(1, 18)
#error Unsupported sudo plugin API
#endif

#define NATIVE_POLICY "/usr/libexec/sudo/sudoers.so"
#define CLOSED_HELPER "/ptw-sudo-gate/closed"
static struct policy_plugin *native;
static void (*native_close)(int, int);
static sudo_printf_t report;
static int opened, closed, checked;
static int (*fatal_register)(void (*)(void));
static int (*fatal_deregister)(void (*)(void));
static pid_t owner_pid;
static int helper_fd = -1;
static char **redirect_info;
static char *redirect_argv[] = { CLOSED_HELPER, NULL };
extern struct policy_plugin ptw_sudo_policy;
static void gate_fatal(void);

/* All labels are constants; never print option values or authentication data. */
static void reject(const char *operation, const char *reason, int error)
{
    if (report != NULL)
        report(SUDO_CONV_ERROR_MSG, "PTW_SUDO_REJECT operation=%s reason=%s errno=%d\n",
            operation, reason, error);
}

static int immutable_fd(const char *path)
{
    struct stat st;
    struct statvfs fs;
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd == -1) {
        reject("immutable_open", "syscall", errno);
        return -1;
    }
    const char *operation = "immutable_fstat";
    if (fstat(fd, &st))
        goto syscall_fail;
    operation = "immutable_fstatvfs";
    if (fstatvfs(fd, &fs))
        goto syscall_fail;
    if (!S_ISREG(st.st_mode) ||
        st.st_uid != 0 || (st.st_mode & 0022) || !(fs.f_flag & ST_RDONLY)) {
        if (report != NULL) report(SUDO_CONV_ERROR_MSG,
            "PTW_SUDO_REJECT operation=immutable_check reason=predicates errno=0 regular=%d root_owned=%d nonwritable=%d readonly=%d\n",
            !!S_ISREG(st.st_mode), st.st_uid == 0, !(st.st_mode & 0022),
            !!(fs.f_flag & ST_RDONLY));
        close(fd);
        errno = EPERM;
        return -1;
    }
    return fd;
syscall_fail:;
    int error = errno;
    reject(operation, "syscall", error);
    close(fd);
    errno = error;
    return -1;
}

static int load_native(void)
{
    char path[64];
    void *handle;
    int fd;
    if (native != NULL)
        return 1;
    fd = immutable_fd(NATIVE_POLICY);
    if (fd == -1)
        return 0;
    snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
    handle = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    close(fd);
    if (handle == NULL) {
        reject("native_load", "dlopen", 0);
        return 0;
    }
    native = dlsym(handle, "sudoers_policy");
    if (native == NULL || native->type != SUDO_POLICY_PLUGIN ||
        native->version != SUDO_API_VERSION || native->open == NULL ||
        native->check_policy == NULL || native->init_session == NULL ||
        native->close == NULL) {
        reject("native_load", "policy_api", 0);
        native = NULL;
        dlclose(handle);
        return 0;
    }
    /* Keep this callback even if check_policy clears the exported field to
     * request sudo's direct-exec optimization. Session cleanup stays native.
     */
    native_close = native->close;
    /* Pinned lib/util/fatal.c: LIFO callbacks run after policy_init_session's
     * audit_error. Register after native open so our close runs before (and
     * deregisters) sudoers_cleanup, which otherwise frees session identity.
     */
    fatal_register = dlsym(RTLD_DEFAULT, "sudo_fatal_callback_register_v1");
    fatal_deregister = dlsym(RTLD_DEFAULT, "sudo_fatal_callback_deregister_v1");
    if (fatal_register == NULL || fatal_deregister == NULL) {
        reject("native_load", "fatal_api", 0);
        native = NULL;
        dlclose(handle);
        return 0;
    }
    return 1;
}

static int gate_open(unsigned int version, sudo_conv_t conv, sudo_printf_t print,
    char * const settings[], char * const user_info[], char * const user_env[],
    char * const options[], const char **errstr)
{
    report = print;
    if (version != SUDO_API_VERSION || opened || !load_native()) {
        reject("open", "unavailable_or_repeated", 0);
        *errstr = "unsupported or unavailable native sudo policy";
        return -1;
    }
    /* No plugin options can substitute sudoers/PAM files in this prerequisite. */
    if (options != NULL && options[0] != NULL) {
        reject("open", "plugin_options", 0);
        *errstr = "closed gate takes no plugin options";
        return -1;
    }
    for (size_t i = 0; settings != NULL && settings[i] != NULL; i++) {
        const char *s = settings[i];
        if (!strcmp(s, "sudoedit=true") || !strcmp(s, "run_shell=true") ||
            !strcmp(s, "login_shell=true") || !strcmp(s, "implied_shell=true") ||
            !strncmp(s, "cmnd_chroot=", 12) || !strncmp(s, "closefrom=", 10)) {
            report(SUDO_CONV_ERROR_MSG,
                "PTW_SUDO_REJECT operation=open reason=mode errno=0 option=%.*s\n",
                (int)strcspn(s, "="), s);
            *errstr = "unsupported closed gate execution mode";
            return -1;
        }
    }
    native->event_alloc = ptw_sudo_policy.event_alloc;
    int ret = native->open(version, conv, print, settings, user_info, user_env,
        options, errstr);
    opened = ret == 1;
    owner_pid = getpid();
    errno = 0;
    if (opened && fatal_register(gate_fatal) != 0) {
        reject("open", "fatal_register", errno);
        *errstr = "closed gate cleanup unavailable";
        /* No session was started. Native open's existing fatal callback owns
         * cleanup when sudo terminates this failed open; do not close early.
         */
        ret = -1;
    }
    report(SUDO_CONV_ERROR_MSG, "PTW_SUDO_STAGE open=%d\n", ret);
    return ret;
}

static void gate_close(int status, int error)
{
    if (opened && !closed) {
        closed = 1;
        fatal_deregister(gate_fatal);
        native_close(status, error);
        report(SUDO_CONV_ERROR_MSG, "PTW_SUDO_STAGE close=%d error=%d\n", status, error);
    }
    if (helper_fd != -1) {
        /* sudo owns the descriptor after check_policy; never close a reused FD. */
        helper_fd = -1;
    }
}

static void gate_fatal(void)
{
    /* Never close the parent's authentication session from a forked child. */
    if (getpid() == owner_pid)
        gate_close(0, ECANCELED);
}

static int gate_check(int argc, char * const argv[], char *env_add[],
    char **info[], char **argv_out[], char **env_out[], const char **errstr)
{
    size_t count = 0, kept = 0;
    if (!opened || closed || checked++) {
        reject("check", "closed_or_repeated", 0);
        *errstr = "closed or repeated sudo request";
        return -1;
    }
    /* The ORIGINAL request goes to native sudoers, unmodified. Never check
     * permission to run the helper instead. Retain native rejection as-is.
     */
    int ret = native->check_policy(argc, argv, env_add, info, argv_out, env_out, errstr);
    report(SUDO_CONV_ERROR_MSG, "PTW_SUDO_STAGE check=%d\n", ret);
    if (ret != 1)
        return ret;
    if (*info == NULL || *argv_out == NULL || *env_out == NULL) {
        report(SUDO_CONV_ERROR_MSG,
            "PTW_SUDO_REJECT operation=check reason=missing_output errno=0 info=%d argv=%d env=%d\n",
            *info != NULL, *argv_out != NULL, *env_out != NULL);
        goto fail;
    }
    while ((*info)[count] != NULL) {
        const char *s = (*info)[count];
        if (!strcmp(s, "sudoedit=true") ||
            !strcmp(s, "intercept=true") || !strcmp(s, "log_subcmds=true") ||
            !strncmp(s, "chroot=", 7)) {
            report(SUDO_CONV_ERROR_MSG,
                "PTW_SUDO_REJECT operation=check reason=option errno=0 option=%.*s\n",
                (int)strcspn(s, "="), s);
            goto fail;
        }
        if (++count > 256) {
            reject("check", "info_limit", 0);
            goto fail;
        }
    }
    helper_fd = immutable_fd(CLOSED_HELPER);
    if (helper_fd == -1)
        goto fail;
    redirect_info = calloc(count + 3, sizeof(char *));
    if (redirect_info == NULL) {
        reject("calloc", "redirect_info", errno);
        goto fail;
    }
    for (size_t i = 0; i < count; i++) {
        const char *entry = (*info)[i];
        /* Preserve native credentials, groups, environment and session options,
         * including use_pty. Native sudo owns terminal selection and monitoring.
         * Only the ensuing executable/argv is replaced by the closed endpoint.
         * Original execfd remains native-owned and is closed by sudo's closefrom.
         */
        if (strncmp(entry, "command=", 8) && strncmp(entry, "execfd=", 7))
            redirect_info[kept++] = (*info)[i];
    }
    redirect_info[kept++] = "command=" CLOSED_HELPER;
    if (asprintf(&redirect_info[kept], "execfd=%d", helper_fd) == -1) {
        reject("asprintf", "execfd", errno);
        goto fail;
    }
    *info = redirect_info;
    *argv_out = redirect_argv;
    report(SUDO_CONV_ERROR_MSG, "PTW_SUDO_STAGE redirect=closed\n");
    return 1;
fail:
    if (helper_fd != -1) {
        close(helper_fd);
        helper_fd = -1;
    }
    free(redirect_info);
    redirect_info = NULL;
    *errstr = "closed sudo execution gate unavailable";
    /* sudo policy_check audits these native-owned outputs before access_denied
     * calls close. Freeing native state here causes use-after-free in audit.
     */
    return -1;
}

static int gate_session(struct passwd *pwd, char **env[], const char **errstr)
{
    if (!opened || closed || !checked || helper_fd == -1) {
        reject("session", "unbound", 0);
        *errstr = "sudo execution gate not bound";
        return -1;
    }
    int ret = native->init_session(pwd, env, errstr);
    report(SUDO_CONV_ERROR_MSG, "PTW_SUDO_STAGE session=%d\n", ret);
    /* Return to policy_init_session for audit first. Its fatal termination
     * invokes gate_fatal, preserving exactly-once native session cleanup.
     */
    return ret;
}

static void gate_register(int version, int (*hook)(struct sudo_hook *))
{
    if (load_native() && native->register_hooks != NULL)
        native->register_hooks(version, hook);
}
static void gate_deregister(int version, int (*hook)(struct sudo_hook *))
{
    if (native != NULL && native->deregister_hooks != NULL)
        native->deregister_hooks(version, hook);
}

/* Missing list/validate/invalidate/version functions intentionally refuse modes
 * outside this execution-only prototype. Non-NULL close forces a sudo monitor.
 */
struct policy_plugin ptw_sudo_policy = {
    .type = SUDO_POLICY_PLUGIN, .version = SUDO_API_VERSION,
    .open = gate_open, .close = gate_close, .check_policy = gate_check,
    .init_session = gate_session, .register_hooks = gate_register,
    .deregister_hooks = gate_deregister
};
#endif
