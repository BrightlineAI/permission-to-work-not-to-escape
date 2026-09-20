/* Trusted sudo command-child checkpoint, pinned Linux x86_64 only.
 * The source-patched frontend calls this AFTER native group/limit/chroot setup
 * and BEFORE native setresuid. Authentication and terminal monitors never call
 * it. This milestone still redirects every approved command to the closed gate.
 * Capability/filter reduction alone is NOT filesystem/process confinement.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <linux/capability.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stdint.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/fsuid.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <sys/wait.h>
#ifdef PTW_CONTROLLER_CHECKPOINT
#error Controller mode must come from the generated, source-bound filter header
#endif
#include <unistd.h>
#ifndef PTW_CLOSED_HELPER
#include <dlfcn.h>
#endif
#include "linuxarena_sudo_child.h"
/* Generated from linuxarena_namespace.py, never a second hand-written filter. */
#include "linuxarena_sudo_filter.h"

void ptw_job_trace(int phase, pid_t subject, pid_t group, int value,
    int result, int error, int tty)
{
#ifdef PTW_REQUEST_RELEASE
    /* Event-loop callbacks only, never async signal handlers. One bounded write
     * per record; preserve the native caller's errno even if logging fails.
     * No descriptor is opened or retained across a command fork. */
    static unsigned int records;
    int saved = errno;
    if (records < 24) {
        records++;
        char line[320];
        int n = snprintf(line, sizeof(line),
            "PTW_JOB phase=%d pid=%ld ppid=%ld pgid=%ld sid=%ld fg=%ld subject=%ld group=%ld value=%d result=%d error=%d\n",
            phase, (long)getpid(), (long)getppid(), (long)getpgrp(),
            (long)getsid(0), (long)tcgetpgrp(tty), (long)subject, (long)group,
            value, result, error);
        if (n > 0 && n < (int)sizeof(line))
            (void)!write(STDERR_FILENO, line, (size_t)n);
    }
    errno = saved;
#else
    (void)phase; (void)subject; (void)group; (void)value;
    (void)result; (void)error; (void)tty;
#endif
}

void ptw_job_wait_observe(pid_t child, int tty)
{
#ifdef PTW_REQUEST_RELEASE
    int saved = errno;
    siginfo_t info = {0};
    /* Never consume status, retry, block, or select an unrelated child. */
    int result = waitid(P_PID, (id_t)child, &info,
        WEXITED | WSTOPPED | WCONTINUED | WNOHANG | WNOWAIT);
    int error = result == -1 ? errno : 0;
    ptw_job_trace(26, child, info.si_pid, info.si_code, result, error, tty);
    ptw_job_trace(27, child, info.si_pid, info.si_status, result, error, tty);
    errno = saved;
#else
    (void)child; (void)tty;
#endif
}

int ptw_job_killpg(int phase, pid_t group, int signo, int tty)
{
    ptw_job_trace(phase, 0, group, signo, 0, 0, tty);
    int result = killpg(group, signo);
    int error = errno;
    ptw_job_trace(phase + 1, 0, group, signo, result, result == -1 ? error : 0, tty);
    errno = error;
    return result;
}

#ifdef PTW_CONTROLLER_CHECKPOINT
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>

/* Only the trusted native monitor opens this connection, after the fork.
 * The child never inherits it. The host authenticates SO_PEERCRED, not a UID
 * or project credential supplied over the wire. This remains a CLOSED probe.
 */
static int controller_admit(pid_t child, int continuation)
{
    int status, result = -1;
    pid_t waited;
    siginfo_t observation;
    int observed;
    /* An early setup failure must remain unreaped until the caller cleans up.
     * Otherwise kill(child) could address a recycled PID after waitpid reaps
     * an exit instead of consuming the expected stop. */
    do {
        memset(&observation, 0, sizeof(observation));
        observed = waitid(P_PID, (id_t)child, &observation, WSTOPPED | WEXITED | WNOWAIT);
    } while (observed < 0 && errno == EINTR);
    if (observed || observation.si_pid != child || observation.si_code != CLD_STOPPED ||
        observation.si_status != SIGSTOP) { errno = EPERM; return -1; }
    do { waited = waitpid(child, &status, WUNTRACED); } while (waited < 0 && errno == EINTR);
    if (waited != child || !WIFSTOPPED(status) || WSTOPSIG(status) != SIGSTOP) {
        errno = EPERM;
        return -1;
    }
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    struct timeval limit = { .tv_sec = 3 };
    struct sockaddr_un address = { .sun_family = AF_UNIX };
    strcpy(address.sun_path, "/observer/admission.sock");
    /* Fixed 32-bit container PID, not command bytes or authority. */
    uint32_t request = (uint32_t)child | (continuation ? UINT32_C(0x80000000) : 0);
    char reply[2];
    if (!setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &limit, sizeof(limit)) &&
        !setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &limit, sizeof(limit)) &&
        !connect(fd, (struct sockaddr *)&address, sizeof(address)) &&
        send(fd, &request, sizeof(request), MSG_NOSIGNAL) == sizeof(request) &&
        !shutdown(fd, SHUT_WR) && recv(fd, reply, sizeof(reply), MSG_WAITALL) == 1 &&
        reply[0] == 'C') result = 0;
    int error = errno;
    close(fd);
    errno = error ? error : EPERM;
    return result;
}
#endif

#if !defined(__linux__) || !defined(__x86_64__) || defined(__ILP32__)
#error Unsupported sudo child checkpoint architecture
#endif

/* Exact fixture setup sets, never payload grants. The placement variant adds
 * only SYS_ADMIN for joining the prepared namespaces before this reduction. */
#ifdef PTW_NAMESPACE_CHECKPOINT
#define PTW_SETUP_MASK UINT64_C(0xa82425fb)
#else
#define PTW_SETUP_MASK UINT64_C(0xa80425fb)
#endif
struct caps { uint64_t effective, permitted, inheritable, bounding, ambient; };
static gid_t groups[256], rgid, egid, sgid;
static int ngroups, prepared;
static uid_t target;
static int command_child, fork_route;
static pid_t fork_parent;
struct placement { ino_t mount, pid, user; };
static struct placement fork_placement;
static int (*request_callback)(int, char *const [], uid_t, uid_t);
static int continuation_fd = -1;
#ifdef PTW_CONTROLLER_CHECKPOINT
static pid_t continuation_child;
#endif

int ptw_child_barrier_fd(void)
{
    return continuation_fd;
}

int ptw_child_request_pin(void)
{
#ifndef PTW_CLOSED_HELPER
    if (request_callback) { errno = EALREADY; return -1; }
    /* Never load a new library or resolve a global, interposable symbol. The
     * pinned native configuration already loaded this exact policy object. */
    void *handle = dlopen("/ptw-sudo-gate/policy.so", RTLD_NOW | RTLD_NOLOAD | RTLD_LOCAL);
    if (!handle) { errno = EPERM; return -1; }
    request_callback = dlsym(handle, "ptw_sudo_request_child_v1");
    dlclose(handle); /* Native plugin loader retains ownership. */
    if (request_callback) return 0;
#endif
    errno = EPERM;
    return -1;
}

int ptw_child_request_verify(char *const environment[], uid_t uid, uid_t euid)
{
    if (!command_child || !request_callback) { errno = EPERM; return -1; }
    int result = request_callback(1, environment, uid, euid);
#ifdef PTW_CONTROLLER_CHECKPOINT
    /* The native parent alone talks to the controller. This anonymous read
     * end conveys no auth/root/socket handle and is closed before any exec.
     * SIGCONT without its second token cannot authorize continuation. */
    char token = 0;
    if (result || continuation_fd < 0 || raise(SIGSTOP) ||
        read(continuation_fd, &token, 1) != 1 || token != 'R') result = -1;
    if (continuation_fd >= 0) close(continuation_fd);
    continuation_fd = -1;
    if (result) { errno = EPERM; return -1; }
    fprintf(stderr, "PTW_CHILD_CONTINUATION checked=1 transport_closed=1\n");
#endif
#ifdef PTW_REQUEST_RELEASE
    /* Populate the already allocated native argv only after the final token.
     * Native sudo still performs its normal final exec and error reporting. */
    if (!result) result = request_callback(2, environment, uid, euid);
#endif
    return result;
}

static int reject(const char *stage)
{
    int error = errno ? errno : EPERM;
    fprintf(stderr, "PTW_CHILD_REJECT stage=%s errno=%d\n", stage, error);
    errno = error;
    return -1;
}

static int placement_read(struct placement *out)
{
    struct stat m, p, u;
    if (stat("/proc/self/ns/mnt", &m) || stat("/proc/self/ns/pid", &p) ||
        stat("/proc/self/ns/user", &u)) return -1;
    *out = (struct placement){m.st_ino, p.st_ino, u.st_ino};
    return 0;
}

static int placement_same(const struct placement *a, const struct placement *b)
{
    return a->mount == b->mount && a->pid == b->pid && a->user == b->user;
}

static int placement_log(const char *stage, pid_t child, const struct placement *p)
{
    /* Fixed numeric metadata only; no argv, environment, paths or auth data.
     * One bounded write preserves records shared by the native processes. */
    char line[384];
    int n = snprintf(line, sizeof(line),
        "PTW_FORK stage=%s route=%d pid=%ld ppid=%ld child=%ld mnt=%llu pidns=%llu userns=%llu\n",
        stage, fork_route, (long)getpid(), (long)getppid(), (long)child,
        (unsigned long long)p->mount, (unsigned long long)p->pid,
        (unsigned long long)p->user);
    if (n <= 0 || n >= (int)sizeof(line) || write(STDERR_FILENO, line, (size_t)n) != n)
        return -1;
    return 0;
}

#ifdef PTW_NAMESPACE_CHECKPOINT
#include "linuxarena_sudo_placement.h"
#endif

void ptw_child_cleanup(void)
{
    if (continuation_fd >= 0) close(continuation_fd);
    continuation_fd = -1;
#ifdef PTW_CONTROLLER_CHECKPOINT
    if (continuation_child > 0 && fork_parent == getpid()) {
        /* The pending child has not been reaped or released to requested code. */
        kill(continuation_child, SIGKILL);
        while (waitpid(continuation_child, NULL, 0) < 0 && errno == EINTR) {}
    }
    continuation_child = 0;
#endif
#ifdef PTW_NAMESPACE_CHECKPOINT
    placement_close();
#endif
}

int ptw_child_pin(void)
{
#ifdef PTW_NAMESPACE_CHECKPOINT
    /* sudo_execute is reached only after original-command approval. Pin before
     * native group/session setup; never move a namespace selection here. */
    if (placement_attempted || command_child || fork_parent) {
        ptw_child_cleanup();
        errno = EPERM;
        return reject("placement_pin_context");
    }
    placement_attempted = 1;
    if (atexit(ptw_child_cleanup) || placement_read(&fork_placement))
        return reject("placement_pin_prepare");
    return placement_open();
#else
    return 0;
#endif
}

static int child_parent_matches(void)
{
#ifdef PTW_NAMESPACE_CHECKPOINT
    /* The native monitor is deliberately outside this PID namespace. */
    return getppid() == 0;
#else
    return getppid() == fork_parent;
#endif
}

int ptw_child_continue(pid_t child)
{
#ifdef PTW_CONTROLLER_CHECKPOINT
    /* Pipe callers arrive directly from fork; PTY monitors arrive only after
     * foreground setup, with signals still blocked and before event dispatch.
     * Consume this private stop before native job control can observe it. */
    if (command_child || fork_parent != getpid() || child <= 0 ||
        continuation_child != child || continuation_fd < 0) {
        ptw_child_cleanup();
        errno = EPERM;
        return reject("continuation_context");
    }
    if (controller_admit(child, 1) || write(continuation_fd, "R", 1) != 1) {
        int error = errno ? errno : EPERM;
        ptw_child_cleanup();
        errno = error;
        return reject("continuation_parent");
    }
    close(continuation_fd);
    continuation_fd = -1;
    continuation_child = 0;
#else
    (void)child;
#endif
    return 0;
}

pid_t ptw_child_fork(pid_t (*native_fork)(void), int route)
{
    int barrier[2];
    struct placement current;
    errno = 0;
    if (command_child || fork_parent || !native_fork || (route != 0 && route != 1)) {
        ptw_child_cleanup();
        return reject("fork_context");
    }
    fork_route = route;
    fork_parent = getpid();
#ifndef PTW_NAMESPACE_CHECKPOINT
    if (placement_read(&fork_placement)) return reject("fork_prepare");
#endif
    if (placement_log("prepare", 0, &fork_placement) || pipe2(barrier, O_CLOEXEC)) {
        ptw_child_cleanup();
        return reject("fork_prepare");
    }
#ifdef PTW_NAMESPACE_CHECKPOINT
    if (placement_select()) {
        int placement_error = errno;
        close(barrier[0]);
        close(barrier[1]);
        errno = placement_error;
        return -1;
    }
#endif
    /* Call the native debug fork, preserving sudo's own at-fork handling.
     * Parent observation precedes child setup. EOF/error cannot release it.
     * This barrier is NOT controller admission or a namespace transition. */
    pid_t child = native_fork();
    int error = errno;
    if (child == 0) {
        close(barrier[1]);
#ifdef PTW_CONTROLLER_CHECKPOINT
        /* The native parent consumes this stop before contacting the host, so
         * sudo's job-control loop cannot interpret it as a user terminal stop.
         * SIGCONT alone cannot authorize: the private pipe must also yield C.
         */
        if (raise(SIGSTOP)) _exit(126);
#endif
        char token = 0;
        int ok = read(barrier[0], &token, 1) == 1 && token == 'C';
#ifdef PTW_CONTROLLER_CHECKPOINT
        continuation_fd = barrier[0];
#else
        close(barrier[0]);
#endif
        /* The host has admitted this child, but it has not entered the target
         * root yet. Bind the original executable/cwd while still visible.
         * Only patched native entry sets the callback; isolated fork tests and
         * the static closed endpoint do not acquire plugin authority. */
        if (ok && request_callback && request_callback(0, NULL, 0, 0)) ok = 0;
#ifdef PTW_NAMESPACE_CHECKPOINT
        if (!ok || placement_enter()) {
            ptw_child_cleanup();
            _exit(126);
        }
#endif
        if (!ok || !child_parent_matches() || placement_read(&current) ||
            !placement_same(&current, &fork_placement) ||
            placement_log("child", 0, &current)) {
            reject("fork_child");
            _exit(126);
        }
        command_child = 1;
        return 0;
    }
    close(barrier[0]);
#ifdef PTW_NAMESPACE_CHECKPOINT
    /* Restore even after fork failure, before any parent continuation. A failed
     * restore closes the barrier and kills only the unreleased child. */
    if (placement_restore()) {
        close(barrier[1]);
        if (child > 0) {
            kill(child, SIGKILL);
            while (waitpid(child, NULL, 0) < 0 && errno == EINTR) {}
        }
        return -1;
    }
#endif
    if (child < 0) {
        close(barrier[1]);
        errno = error;
        return reject("native_fork");
    }
    if (placement_read(&current) || !placement_same(&current, &fork_placement) ||
        placement_log("parent", child, &current) ||
#ifdef PTW_CONTROLLER_CHECKPOINT
        controller_admit(child, 0) ||
#endif
        write(barrier[1], "C", 1) != 1) {
        error = errno ? errno : EPERM;
        close(barrier[1]);
        /* Only our not-yet-released child; never another job or a name lookup. */
        kill(child, SIGKILL);
        while (waitpid(child, NULL, 0) < 0 && errno == EINTR) {}
        errno = error;
        return reject("fork_parent");
    }
#ifdef PTW_CONTROLLER_CHECKPOINT
    continuation_fd = barrier[1];
    continuation_child = child;
    if (route == 0 && ptw_child_continue(child)) return -1;
#else
    close(barrier[1]);
#endif
    return child;
}

static int child_placement(const char *stage)
{
    struct placement current;
    if (!command_child || !child_parent_matches() ||
        placement_read(&current) || !placement_same(&current, &fork_placement) ||
        placement_log(stage, 0, &current)) return reject("child_placement");
    return 0;
}

int ptw_child_descriptors(void)
{
    /* The static endpoint has crossed exec. No authentication, old-root,
     * namespace, barrier or controller FD may survive alongside stdio. */
    for (int fd = 0; fd < 3; fd++)
        if (fcntl(fd, F_GETFD) < 0) return reject("exec_stdio");
    DIR *directory = opendir("/proc/self/fd");
    if (!directory) return reject("exec_descriptors");
    int scan = dirfd(directory), bad = 0;
    struct dirent *entry;
    errno = 0;
    while ((entry = readdir(directory)) != NULL) {
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        unsigned fd = 0;
        const char *c = entry->d_name;
        for (; *c; c++) {
            if (*c < '0' || *c > '9' || fd > 100000000) { bad = 1; break; }
            fd = fd * 10 + (unsigned)(*c - '0');
        }
        if (bad || (fd > 2 && fd != (unsigned)scan)) { bad = 1; break; }
    }
    if (errno) bad = 1;
    if (closedir(directory)) bad = 1;
    if (bad) return reject("exec_descriptors");
    fprintf(stderr, "PTW_CHILD_FDS stdio_only=1\n");
    return 0;
}

int ptw_child_exec_observe(void)
{
    struct placement current;
    if (ptw_child_descriptors() || placement_read(&current))
        return reject("exec_descriptors");
    /* Static state does not survive exec; observer checks relation to fork log. */
    fork_route = -1;
    if (placement_log("exec", 0, &current)) return reject("exec_observation");
    return 0;
}

int ptw_child_placement_effect(void)
{
#ifdef PTW_NAMESPACE_CHECKPOINT
    struct placement location;
    if (placement_read(&location)) return reject("confined_placement");
    /* Fixed synthetic effects only. Never open account stores or accept paths
     * from argv/environment. Namespace visibility is not Landlock admission. */
    const char *absent[] = { "/ptw-placement", "/ptw-sudo-gate", "/private",
                            "/etc/shadow", "/observer" };
    for (unsigned i = 0; i < sizeof(absent) / sizeof(absent[0]); i++) {
        struct stat st;
        errno = 0;
        if (lstat(absent[i], &st) != -1 || errno != ENOENT)
            return reject("exec_private_visibility");
    }
    char path[96];
    snprintf(path, sizeof(path), "/tmp/ptw-placement-%u-%ld", (unsigned)getuid(), (long)getpid());
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) return reject("exec_useful_open");
    int bad_write = write(fd, "placed\n", 7) != 7;
    int bad_close = close(fd);
    if (bad_write || bad_close) return reject("exec_useful_write");
    fprintf(stderr, "PTW_CHILD_PLACEMENT private_absent=1 tmp_write=1\n");
    fprintf(stderr, "PTW_CONFINED_EFFECT uid=%u pid=%ld mnt=%llu pidns=%llu userns=%llu\n",
        (unsigned)getuid(), (long)getpid(), (unsigned long long)location.mount,
        (unsigned long long)location.pid, (unsigned long long)location.user);
#endif
    return 0;
}

static int caps_read(struct caps *out)
{
    struct __user_cap_header_struct header = { _LINUX_CAPABILITY_VERSION_3, 0 };
    struct __user_cap_data_struct data[2] = {{0}};
    memset(out, 0, sizeof(*out));
    if (syscall(SYS_capget, &header, data) != 0)
        return -1;
    out->effective = data[0].effective | ((uint64_t)data[1].effective << 32);
    out->permitted = data[0].permitted | ((uint64_t)data[1].permitted << 32);
    out->inheritable = data[0].inheritable | ((uint64_t)data[1].inheritable << 32);
    for (unsigned bit = 0; bit < 64; bit++) {
        errno = 0;
        int b = prctl(PR_CAPBSET_READ, bit, 0, 0, 0);
        if (b == -1 && errno == EINVAL) break;
        if (b < 0) return -1;
        int a = prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET, bit, 0, 0);
        if (a < 0) return -1;
        out->bounding |= (uint64_t)b << bit;
        out->ambient |= (uint64_t)a << bit;
    }
    errno = 0;
    return 0;
}

static int caps_set(uint64_t mask)
{
    struct __user_cap_header_struct header = { _LINUX_CAPABILITY_VERSION_3, 0 };
    struct __user_cap_data_struct data[2] = {
        { .effective = (uint32_t)mask, .permitted = (uint32_t)mask },
        { .effective = (uint32_t)(mask >> 32), .permitted = (uint32_t)(mask >> 32) }
    };
    return syscall(SYS_capset, &header, data);
}

int ptw_child_before_uid(uid_t uid, uid_t euid)
{
    struct caps before, after;
    uid_t r, e, s;
    uint64_t ceiling = uid == 0 ? PTW_PAYLOAD_MASK : 0;
    uint64_t active = uid == 0 ? ceiling : UINT64_C(1) << CAP_SETUID;
    errno = 0;
    if (child_placement("before_uid")) return -1;
    if (prepared || uid != euid || (uid != 0 && uid != 1000) ||
        getresuid(&r, &e, &s) || r != 0 || e != 0 || s != 0 ||
        prctl(PR_GET_SECUREBITS, 0, 0, 0, 0) != 0 || caps_read(&before) ||
        before.effective != PTW_SETUP_MASK || before.permitted != PTW_SETUP_MASK ||
        before.bounding != PTW_SETUP_MASK || before.inheritable || before.ambient)
        return reject("initial_state");
    if (getresgid(&rgid, &egid, &sgid) ||
        (ngroups = getgroups(256, groups)) < 0)
        return reject("native_groups");
    if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0))
        return reject("ambient_clear");
    /* Inheritable is already required empty. Clear it explicitly with capset
     * while keeping SETPCAP until the complete bounding reduction is checked. */
    if (caps_set(before.permitted)) return reject("inheritable_clear");
    for (unsigned bit = 0; bit < 64; bit++) {
        if ((before.bounding & (UINT64_C(1) << bit)) &&
            !(ceiling & (UINT64_C(1) << bit)) &&
            prctl(PR_CAPBSET_DROP, bit, 0, 0, 0))
            return reject("bounding_drop");
    }
    if (caps_set(active)) return reject("active_drop");
    if (caps_read(&after) || after.bounding != ceiling ||
        after.effective != active || after.permitted != active ||
        after.inheritable || after.ambient)
        return reject("reduction_state");
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) ||
        prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1)
        return reject("no_new_privileges");
    struct sock_fprog program = {
        .len = sizeof(ptw_socket_filter) / sizeof(ptw_socket_filter[0]),
        .filter = ptw_socket_filter
    };
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program) ||
        prctl(PR_GET_SECCOMP, 0, 0, 0, 0) != SECCOMP_MODE_FILTER)
        return reject("seccomp_install");
    target = uid;
    prepared = 1;
    fprintf(stderr, "PTW_CHILD_STAGE before_uid=%u filter=%s\n",
        (unsigned)uid, PTW_FILTER_SHA256);
    return 0;
}

int ptw_child_observe(void)
{
    struct caps current;
    uid_t r, e, s;
    errno = 0;
    if (getresuid(&r, &e, &s) || r != e || e != s || (r != 0 && r != 1000))
        return reject("final_ids");
    uint64_t ceiling = r == 0 ? PTW_PAYLOAD_MASK : 0;
    if (caps_read(&current) || current.effective != ceiling ||
        current.permitted != ceiling || current.bounding != ceiling ||
        current.inheritable || current.ambient ||
        prctl(PR_GET_SECUREBITS, 0, 0, 0, 0) != 0 ||
        prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1 ||
        prctl(PR_GET_SECCOMP, 0, 0, 0, 0) != SECCOMP_MODE_FILTER)
        return reject("final_caps_filter");
    fprintf(stderr, "PTW_CHILD_STATE uid=%u effective=%llx permitted=%llx "
        "bounding=%llx inheritable=0 ambient=0 securebits=0 nnp=1 seccomp=2\n",
        (unsigned)r, (unsigned long long)current.effective,
        (unsigned long long)current.permitted, (unsigned long long)current.bounding);
    return 0;
}

int ptw_child_after_uid(uid_t uid, uid_t euid)
{
    gid_t current[256], r, e, s;
    errno = 0;
    if (!prepared || uid != target || euid != target ||
        getuid() != target || geteuid() != target ||
        (uid_t)setfsuid((uid_t)-1) != target ||
        getresgid(&r, &e, &s) || r != rgid || e != egid || s != sgid ||
        (gid_t)setfsgid((gid_t)-1) != egid ||
        getgroups(256, current) != ngroups ||
        memcmp(groups, current, (size_t)ngroups * sizeof(gid_t)))
        return reject("native_identity_changed");
    if (ptw_child_observe() || child_placement("after_uid")) return -1;
    prepared = 0;
    return 0;
}
