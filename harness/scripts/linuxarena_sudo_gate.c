/* Native sudo 1.9.9 delegation prerequisite.
 * Build against the verified upstream sudo_plugin.h (API 1.18).
 * Default builds remain closed. The separately compiled release fixture requires
 * namespace placement, two controller admissions and static Landlock stages.
 * No caller option or environment variable enables release in a closed build.
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
#ifdef PTW_REQUEST_RELEASE
#include "linuxarena_sudo_release.h"
#endif

#ifdef PTW_CLOSED_HELPER
#ifdef PTW_CHECKPOINT_HELPER
#include "linuxarena_sudo_child.h"
#include <sys/socket.h>
#include <sys/syscall.h>
#include "linuxarena_sudo_landlock.h"
#endif
#ifdef PTW_LANDLOCK_HELPER
/* This fixed physical control is not requested code or a task solution. */
#ifdef PTW_SCOPE_HELPER
static int scope_effect(int confined)
{
    const char *paths[] = {"/probe/work/canary", "/probe/other/canary"};
    for (unsigned i = 0; i < 2; i++) {
        errno = 0;
        int fd = open(paths[i], O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
        if (confined && i == 1) {
            if (fd >= 0) { close(fd); return 124; }
            if (errno != EACCES) return 124;
        } else {
            char value[24] = {0};
            if (fd < 0) return 124;
            ssize_t count = read(fd, value, sizeof(value));
            int error = close(fd);
            if (error || count != 23 || memcmp(value, "synthetic scope control", 23)) return 124;
        }
    }
    fprintf(stderr, "PTW_CHILD_SCOPE stage=%s work=readable other=%s\n",
        confined ? "after" : "before", confined ? "EACCES" : "readable");
    return 0;
}
#endif
static int landlock_failure(const char *stage)
{
    fprintf(stderr, "PTW_CHILD_REJECT stage=%s errno=%d\n", stage, errno ? errno : EPERM);
    return 124;
}

static int landlock_cwd(const char *stage)
{
    char cwd[sizeof(ptw_landlock_cwd)];
    if (getcwd(cwd, sizeof(cwd)) == NULL)
        return landlock_failure("landlock_getcwd");
    if (strcmp(cwd, ptw_landlock_cwd)) {
        errno = EPERM;
        return landlock_failure("landlock_cwd_mismatch");
    }
    if (fprintf(stderr, "PTW_CHILD_CWD stage=%s cwd=%s\n", stage, cwd) < 0)
        return landlock_failure("landlock_cwd_report");
    return 0;
}

static int landlock_exec(int argc, char **argv)
{
    /* The closed fixture accepts no caller environment. Fresh state belongs to
     * the authenticated target, outside every Landlock resource grant. No
     * account home, shared installation or existing permission is changed. */
    char state[] = PTW_LANDLOCK_STATE "/closed-XXXXXX";
    struct stat st;
    if (mkdtemp(state) == NULL) return landlock_failure("landlock_state_create");
    if (lstat(state, &st)) return landlock_failure("landlock_state_stat");
    if (!S_ISDIR(st.st_mode) || (st.st_mode & 07777) != 0700 || st.st_uid != geteuid()) {
        errno = EPERM;
        return landlock_failure("landlock_state_identity");
    }
    char home[sizeof(state) + sizeof("HOME=")];
    char xdg[sizeof(state) + sizeof("XDG_STATE_HOME=")];
    snprintf(home, sizeof(home), "HOME=%s", state);
    snprintf(xdg, sizeof(xdg), "XDG_STATE_HOME=%s", state);
    char *const env[] = {"PATH=/usr/local/bin:/usr/bin:/bin", "LC_ALL=C", home, xdg, NULL};
    fprintf(stderr, "PTW_CHILD_STATE_DIR before=private\n");
    fflush(NULL);
#ifdef PTW_REQUEST_RELEASE
    /* Replace only the immutable endpoint's arguments, never its policy flags.
     * Original environment stays inert data until the confined final exec. */
    size_t prefix = sizeof(ptw_landlock_argv) / sizeof(ptw_landlock_argv[0]) - 2;
    char *launch[PTW_RELEASE_MAX + 128];
    if (argc < 2 || argc > PTW_RELEASE_MAX || prefix > 128) {
        errno = E2BIG; return landlock_failure("release_argv_size");
    }
    for (size_t i = 0; i < prefix; i++) launch[i] = ptw_landlock_argv[i];
    launch[prefix++] = "--confined";
    for (int i = 2; i < argc; i++) launch[prefix++] = argv[i];
    launch[prefix] = NULL;
    execve(launch[0], launch, env);
#else
    (void)argc; (void)argv;
    execve(ptw_landlock_argv[0], ptw_landlock_argv, env);
#endif
    return landlock_failure("landlock_exec");
}

static int landlock_state_denied(void)
{
    const char *home = getenv("HOME"), *xdg = getenv("XDG_STATE_HOME");
    const char prefix[] = PTW_LANDLOCK_STATE "/closed-";
    if (!home || !xdg || strcmp(home, xdg) ||
        strncmp(home, prefix, sizeof(prefix) - 1) ||
        strlen(home) != sizeof(prefix) - 1 + 6 ||
        strspn(home + sizeof(prefix) - 1,
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") != 6) {
        errno = EPERM;
        return landlock_failure("landlock_state_environment");
    }
    errno = 0;
    int fd = open(home, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd != -1) {
        close(fd);
        errno = EPERM;
        return landlock_failure("landlock_state_readable");
    }
    if (errno != EACCES) return landlock_failure("landlock_state_denial");
    fprintf(stderr, "PTW_CHILD_STATE_DIR after=EACCES\n");
    return 0;
}
#endif
int main(int argc, char **argv)
{
    /* Static binary: native-approved environment cannot load project libraries. */
#ifdef PTW_CHECKPOINT_HELPER
    if (ptw_child_observe() != 0)
        return 124;
#ifdef PTW_LANDLOCK_HELPER
    /* Both stages are immutable code. Native credentials precede nono/Landlock;
     * only the separate release build can execute the retained request. */
#ifdef PTW_REQUEST_RELEASE
    struct release_view release;
    if (release_parse(argc, argv, &release)) return landlock_failure("release_frame");
    if (strcmp(release.cwd, ptw_landlock_cwd)) return landlock_failure("release_scope_cwd");
    if (!strcmp(argv[1], "--pending")) {
        int fd = release_bind(&release);
        if (fd < 0) return landlock_failure("release_pending_binding");
        close(fd);
#else
    if (argc == 1) {
#endif
        if (ptw_child_exec_observe()) return 124;
        /* Namespace entry resets cwd to /. Restore the already granted cwd
         * from the same immutable specification as nono's argv, after native
         * target credentials are established. Never grant the inherited cwd. */
        if (chdir(ptw_landlock_cwd)) return landlock_failure("landlock_chdir");
        if (landlock_cwd("before_nono")) return 124;
        int control = open("/probe-denied/canary", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
        if (control < 0) return landlock_failure("landlock_control_open");
        if (close(control)) return landlock_failure("landlock_control_close");
        fprintf(stderr, "PTW_CHILD_LANDLOCK before=readable\n");
#ifdef PTW_SCOPE_HELPER
        if (scope_effect(0)) return 124;
#endif
        return landlock_exec(argc, argv);
    }
    if (
#ifndef PTW_REQUEST_RELEASE
        argc != 2 ||
#endif
        strcmp(argv[1], "--confined")) {
        errno = EINVAL;
        return landlock_failure("landlock_mode");
    }
    if (ptw_child_descriptors()) return 124;
    if (landlock_cwd("after_nono")) return 124;
    if (landlock_state_denied()) return 124;
    errno = 0;
    int control = open("/probe-denied/canary", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (control != -1) {
        close(control);
        errno = EPERM;
        return landlock_failure("landlock_readable");
    }
    if (errno != EACCES) return landlock_failure("landlock_denial");
    fprintf(stderr, "PTW_CHILD_LANDLOCK after=EACCES\n");
#ifdef PTW_SCOPE_HELPER
    if (scope_effect(1)) return 124;
#endif
    if (ptw_child_placement_effect()) return 124;
#else
    (void)argc;
    (void)argv;
    if (ptw_child_exec_observe()) return 124;
#endif
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
#ifdef PTW_REQUEST_RELEASE
    int executable = release_bind(&release);
    if (executable < 0) return landlock_failure("release_confined_binding");
    /* Split the copied vector only after all controls; no descriptors survive
     * the ELF exec. fexecve pins the checked inode through final execution. */
    release.args[-1] = NULL;
    fprintf(stderr, "PTW_REQUEST_RELEASE confined=1\n");
    ptw_job_trace(30, getpid(), getpgrp(), 0, 0, 0, STDIN_FILENO);
    fflush(NULL);
    fexecve(executable, release.args, release.env);
    int error = errno;
    close(executable); errno = error;
    return landlock_failure("release_exec");
#endif
#else
    (void)argc;
    (void)argv;
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
static int session_attempted;
static char **redirect_info;
#ifdef PTW_REQUEST_RELEASE
static char *redirect_argv[PTW_RELEASE_MAX + 1] = { CLOSED_HELPER, NULL };
static char release_executable[384], release_directory[384], release_envc[16];
static int release_prepared;
#else
static char *redirect_argv[] = { CLOSED_HELPER, NULL };
#endif
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

#include "linuxarena_sudo_request.h"

/* Resolved with RTLD_NOLOAD by the verified frontend. Not a plugin option or
 * an agent-callable service; the native plugin remains loaded through cleanup. */
int ptw_sudo_request_child_v1(int phase, char *const env[], uid_t uid, uid_t euid)
{
#ifdef PTW_REQUEST_RELEASE
    if (phase == 2) {
        struct stat ns;
        if (!opened || closed || !request.session || request.child_verified != 1 ||
            release_prepared++ || request.child_pid != getpid() ||
            stat("/proc/self/ns/pid", &ns) || ns.st_ino != request.child_namespace ||
            getuid() != uid || geteuid() != euid ||
            !vector_matches(&request.environment, env) ||
            release_identity(release_executable, &request.executable, 0) ||
            release_identity(release_directory, &request.directory, 1)) {
            errno = EPERM; return -1;
        }
        size_t n = 0;
        snprintf(release_envc, sizeof(release_envc), "%zu", request.environment.count);
        redirect_argv[n++] = CLOSED_HELPER;
        redirect_argv[n++] = "--pending";
        redirect_argv[n++] = (char *)request_value("command");
        redirect_argv[n++] = request.cwd;
        redirect_argv[n++] = release_executable;
        redirect_argv[n++] = release_directory;
        redirect_argv[n++] = release_envc;
        for (size_t i = 0; i < request.environment.count; i++)
            redirect_argv[n++] = request.environment.items[i];
        redirect_argv[n++] = "";
        for (size_t i = 0; i < request.argv.count; i++)
            redirect_argv[n++] = request.argv.items[i];
        redirect_argv[n] = NULL;
        report(SUDO_CONV_ERROR_MSG, "PTW_REQUEST_RELEASE prepared=1\n");
        return 0;
    }
#endif
    if (!opened || closed || !session_attempted || request_child(phase, env, uid, euid))
        return -1;
    report(SUDO_CONV_ERROR_MSG,
        "PTW_SUDO_CHILD_REQUEST phase=%d pid=%ld argc=%zu envc=%zu\n",
        phase, (long)getpid(), request.argv.count, request.environment.count);
    return 0;
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
        request_free();
        /* Terminal restoration can end with escape bytes and no newline.
         * Frame our cleanup record independently; retain the raw transcript
         * and strict stage parser instead of stripping terminal output. */
        report(SUDO_CONV_ERROR_MSG, "\nPTW_SUDO_STAGE close=%d error=%d\n", status, error);
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
#ifdef PTW_REQUEST_RELEASE
        if (!release_option_supported(s)) {
            reject("release", "unsupported_native_option", 0);
            goto fail;
        }
#endif
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
    if (request_capture(*info, *argv_out)) {
        reject("request", "capture", errno);
        goto fail;
    }
    report(SUDO_CONV_ERROR_MSG,
        "PTW_SUDO_REQUEST captured=1 argc=%zu caller_uid=%u caller_gid=%u executable_dev=%llu executable_ino=%llu cwd_dev=%llu cwd_ino=%llu\n",
        request.argv.count, (unsigned)request.caller_uid, (unsigned)request.caller_gid,
        (unsigned long long)request.executable.st_dev, (unsigned long long)request.executable.st_ino,
        (unsigned long long)request.directory.st_dev, (unsigned long long)request.directory.st_ino);
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
    request_free();
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
    if (!opened || closed || !checked || helper_fd == -1 || !request.ready || session_attempted++) {
        reject("session", "unbound", 0);
        *errstr = "sudo execution gate not bound";
        return -1;
    }
    int ret = native->init_session(pwd, env, errstr);
    if (ret == 1 && request_finish(env ? *env : NULL)) {
        reject("request", "session_binding", errno);
        *errstr = "native approved request binding changed";
        ret = -1;
    }
    if (ret == 1)
        report(SUDO_CONV_ERROR_MSG, "PTW_SUDO_REQUEST session=1 envc=%zu\n", request.environment.count);
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
