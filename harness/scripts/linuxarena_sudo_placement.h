/* Closed namespace-placement prerequisite, included only by the derived
 * frontend. No requested-command release or caller-selected paths. */
#include <sched.h>
#include <sys/statvfs.h>

static int target_mount = -1, target_pid = -1, target_root = -1, saved_pid = -1;
static struct placement target_placement;
static int placement_attempted, placement_ready;

static void placement_close(void)
{
    int error = errno;
    int *fds[] = { &target_mount, &target_pid, &target_root, &saved_pid };
    for (unsigned i = 0; i < sizeof(fds) / sizeof(fds[0]); i++) {
        if (*fds[i] >= 0) close(*fds[i]);
        *fds[i] = -1;
    }
    placement_ready = 0;
    errno = error;
}

static int caps_read(struct caps *);

static int placement_identity(void)
{
    uid_t r, e, s;
    gid_t gr, ge, gs;
    struct caps c;
    if (getresuid(&r, &e, &s) || getresgid(&gr, &ge, &gs) || caps_read(&c))
        return reject("placement_identity");
    /* Query only: -1 cannot be an assigned filesystem ID. No auth contents,
     * environment, command text or broad process dump enters this record. */
    unsigned fsuid = (unsigned)setfsuid((uid_t)-1);
    unsigned fsgid = (unsigned)setfsgid((gid_t)-1);
    char line[512];
    int n = snprintf(line, sizeof(line),
        "PTW_PLACEMENT_ID uid=%u euid=%u suid=%u fsuid=%u "
        "gid=%u egid=%u sgid=%u fsgid=%u effective=%llx permitted=%llx "
        "inheritable=%llx bounding=%llx ambient=%llx\n",
        (unsigned)r, (unsigned)e, (unsigned)s, fsuid,
        (unsigned)gr, (unsigned)ge, (unsigned)gs, fsgid,
        (unsigned long long)c.effective, (unsigned long long)c.permitted,
        (unsigned long long)c.inheritable, (unsigned long long)c.bounding,
        (unsigned long long)c.ambient);
    if (n <= 0 || n >= (int)sizeof(line)) {
        errno = EOVERFLOW;
        return reject("placement_identity_size");
    }
    ssize_t written = write(STDERR_FILENO, line, (size_t)n);
    if (written != n) {
        if (written >= 0) errno = EIO;
        return reject("placement_identity_write");
    }
    return 0;
}

/* Decimal-only, exact bounded wire format. The trusted fixture creates this
 * file in a fresh read-only mount, never in the mutable namespace. */
static int placement_numbers(const char *text, size_t size, uint64_t out[4])
{
    size_t offset = 0;
    for (unsigned i = 0; i < 4; i++) {
        uint64_t value = 0;
        size_t start = offset;
        while (offset < size && text[offset] >= '0' && text[offset] <= '9') {
            unsigned digit = (unsigned)(text[offset++] - '0');
            if (value > (UINT64_MAX - digit) / 10) return -1;
            value = value * 10 + digit;
        }
        if (offset == start || !value || offset >= size ||
            text[offset++] != (i == 3 ? '\n' : ' ')) return -1;
        out[i] = value;
    }
    return offset == size && out[0] > 1 && out[0] <= INT32_MAX ? 0 : -1;
}

static int placement_open(void)
{
    struct stat config, mount, pid, user, root, current_root, saved;
    struct statvfs fs;
    char data[128], path[96];
    uint64_t numbers[4];
    int fd = -1, proc = -1, error;
    const char *stage;
    if (placement_identity()) return -1;
    /* Stop at the FIRST failed operation; later successful syscalls and close
     * must not replace its errno. Predicate failures have explicit labels. */
#define PLACEMENT_CALL(label, failed) do { stage = label; if (failed) goto fail; } while (0)
#define PLACEMENT_REQUIRE(label, valid) do { \
    stage = label; if (!(valid)) { errno = EPERM; goto fail; } \
} while (0)
    PLACEMENT_CALL("placement_config_open",
        (fd = open("/ptw-placement/target", O_RDONLY | O_NOFOLLOW | O_CLOEXEC)) < 0);
    ssize_t size = read(fd, data, sizeof(data));
    PLACEMENT_CALL("placement_config_read", size < 0);
    PLACEMENT_CALL("placement_config_stat", fstat(fd, &config));
    PLACEMENT_CALL("placement_config_statvfs", fstatvfs(fd, &fs));
    PLACEMENT_REQUIRE("placement_config_size", size > 0 &&
        size < (ssize_t)sizeof(data) && config.st_size == size);
    PLACEMENT_REQUIRE("placement_config_regular", S_ISREG(config.st_mode));
    PLACEMENT_REQUIRE("placement_config_owner", config.st_uid == 0);
    PLACEMENT_REQUIRE("placement_config_mode", !(config.st_mode & 0022));
    PLACEMENT_REQUIRE("placement_config_readonly", fs.f_flag & ST_RDONLY);
    PLACEMENT_REQUIRE("placement_config_format", !placement_numbers(data, (size_t)size, numbers));
    close(fd);
    fd = -1;
    /* Pin the proc directory before opening its magic namespace/root links.
     * Inode bindings reject a reused keeper PID or substituted namespace. */
    snprintf(path, sizeof(path), "/proc/%llu", (unsigned long long)numbers[0]);
    PLACEMENT_CALL("placement_process_open",
        (proc = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)) < 0);
    PLACEMENT_CALL("placement_mount_open",
        (target_mount = openat(proc, "ns/mnt", O_RDONLY | O_CLOEXEC)) < 0);
    PLACEMENT_CALL("placement_pid_open",
        (target_pid = openat(proc, "ns/pid", O_RDONLY | O_CLOEXEC)) < 0);
    PLACEMENT_CALL("placement_root_open",
        (target_root = openat(proc, "root", O_RDONLY | O_DIRECTORY | O_CLOEXEC)) < 0);
    PLACEMENT_CALL("placement_mount_stat", fstat(target_mount, &mount));
    PLACEMENT_CALL("placement_pid_stat", fstat(target_pid, &pid));
    PLACEMENT_CALL("placement_root_stat", fstat(target_root, &root));
    PLACEMENT_CALL("placement_user_stat", fstatat(proc, "ns/user", &user, 0));
    PLACEMENT_CALL("placement_current_root_stat", stat("/", &current_root));
    PLACEMENT_REQUIRE("placement_mount_binding", mount.st_ino == numbers[1]);
    PLACEMENT_REQUIRE("placement_pid_binding", pid.st_ino == numbers[2]);
    PLACEMENT_REQUIRE("placement_user_binding", user.st_ino == numbers[3]);
    PLACEMENT_REQUIRE("placement_user_domain", user.st_ino == fork_placement.user);
    PLACEMENT_REQUIRE("placement_mount_isolation", mount.st_ino != fork_placement.mount);
    PLACEMENT_REQUIRE("placement_pid_isolation", pid.st_ino != fork_placement.pid);
    PLACEMENT_REQUIRE("placement_root_isolation",
        root.st_dev != current_root.st_dev || root.st_ino != current_root.st_ino);
    close(proc);
    proc = -1;
    target_placement = (struct placement){mount.st_ino, pid.st_ino, user.st_ino};
    PLACEMENT_CALL("placement_saved_pid_open",
        (saved_pid = open("/proc/self/ns/pid_for_children", O_RDONLY | O_CLOEXEC)) < 0);
    PLACEMENT_CALL("placement_saved_pid_stat", fstat(saved_pid, &saved));
    PLACEMENT_REQUIRE("placement_saved_pid_binding", saved.st_ino == fork_placement.pid);
#undef PLACEMENT_CALL
#undef PLACEMENT_REQUIRE
    placement_ready = 1;
    return 0;
fail:
    error = errno;
    if (fd >= 0) close(fd);
    if (proc >= 0) close(proc);
    placement_close();
    errno = error;
    return reject(stage);
}

static int placement_select(void)
{
    struct placement current;
    struct stat selected;
    /* Handles were pinned before native group/session setup. No proc handle is
     * reopened under the target filesystem GID. Verify the monitor has not
     * changed domains, and select only immediately around the command fork. */
    const char *stage = "placement_select_context";
    if (!placement_ready) {
        errno = EPERM;
        goto fail;
    }
    stage = "placement_select_observe";
    if (placement_read(&current) || stat("/proc/self/ns/pid_for_children", &selected))
        goto fail;
    stage = "placement_select_context";
    if (!placement_same(&current, &fork_placement) || selected.st_ino != fork_placement.pid) {
        errno = EPERM;
        goto fail;
    }
    stage = "placement_select_pid";
    if (setns(target_pid, CLONE_NEWPID)) goto fail;
    return 0;
fail:
    placement_close(); /* preserves errno */
    return reject(stage);
}

static int placement_restore(void)
{
    struct stat restored;
    int bad = saved_pid < 0 || setns(saved_pid, CLONE_NEWPID) ||
        stat("/proc/self/ns/pid_for_children", &restored) ||
        restored.st_ino != fork_placement.pid;
    placement_close();
    return bad ? reject("placement_restore_pid") : 0;
}

static int placement_enter(void)
{
    /* setns does not change root/cwd. Finish both while setup privileges remain,
     * then close EVERY old-root/namespace descriptor before native UID setup. */
    int bad = setns(target_mount, CLONE_NEWNS) || fchdir(target_root) ||
        chroot(".") || chdir("/");
    placement_close();
    if (bad) return reject("placement_enter");
    fork_placement = target_placement;
    return 0;
}
