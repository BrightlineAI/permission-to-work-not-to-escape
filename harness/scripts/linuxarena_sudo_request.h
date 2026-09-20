/* Native-approved request retention for the CLOSED delegation prerequisite.
 * No serialization, broker API or requested-command execution lives here.
 * Copies belong to the delegator; native audit/session storage stays native.
 */
#include <stdint.h>

#define PTW_REQUEST_ITEMS 256
#define PTW_REQUEST_BYTES 131072
struct request_vector { char **items; size_t count, bytes; };
struct approved_request {
    struct request_vector info, argv, environment;
    char **native_info, **native_argv;
    char *cwd;
    int executable_fd, cwd_fd, ready, session;
    struct stat executable, directory;
    uid_t caller_uid;
    gid_t caller_gid;
    pid_t child_pid;
    ino_t child_namespace;
    int child_attempted, child_verified;
};
static struct approved_request request = { .executable_fd = -1, .cwd_fd = -1 };

static void vector_free(struct request_vector *v)
{
    for (size_t i = 0; i < v->count; i++) free(v->items[i]);
    free(v->items);
    *v = (struct request_vector){0};
}

static int vector_copy(struct request_vector *out, char *const input[], int metadata)
{
    if (!input) { errno = EINVAL; return -1; }
    struct request_vector v = {0};
    v.items = calloc(PTW_REQUEST_ITEMS + 1, sizeof(char *));
    if (!v.items) return -1;
    for (; input[v.count]; v.count++) {
        if (v.count == PTW_REQUEST_ITEMS) { errno = E2BIG; goto fail; }
        size_t size = strnlen(input[v.count], PTW_REQUEST_BYTES + 1);
        if (size >= PTW_REQUEST_BYTES || size + 1 > PTW_REQUEST_BYTES - v.bytes) {
            errno = E2BIG;
            goto fail;
        }
        if (metadata) {
            const char *equals = memchr(input[v.count], '=', size);
            if (!equals || equals == input[v.count]) { errno = EINVAL; goto fail; }
            size_t key = (size_t)(equals - input[v.count]);
            for (size_t i = 0; i < v.count; i++) {
                if (!strncmp(v.items[i], input[v.count], key) && v.items[i][key] == '=') {
                    errno = EINVAL;
                    goto fail;
                }
            }
        }
        v.items[v.count] = strdup(input[v.count]);
        if (!v.items[v.count]) goto fail;
        v.bytes += size + 1;
    }
    *out = v;
    return 0;
fail:;
    int error = errno;
    vector_free(&v);
    errno = error;
    return -1;
}

static const char *request_value(const char *key)
{
    size_t length = strlen(key);
    for (size_t i = 0; i < request.info.count; i++) {
        const char *entry = request.info.items[i];
        if (!strncmp(entry, key, length) && entry[length] == '=') return entry + length + 1;
    }
    return NULL;
}

static int vector_matches(const struct request_vector *v, char *const input[])
{
    if (!input) return 0;
    for (size_t i = 0; i < v->count; i++)
        if (!input[i] || strcmp(input[i], v->items[i])) return 0;
    return input[v->count] == NULL;
}

static int same_file(const struct stat *a, const struct stat *b)
{
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino &&
        a->st_mode == b->st_mode && a->st_uid == b->st_uid && a->st_gid == b->st_gid &&
        a->st_size == b->st_size && a->st_mtim.tv_sec == b->st_mtim.tv_sec &&
        a->st_mtim.tv_nsec == b->st_mtim.tv_nsec &&
        a->st_ctim.tv_sec == b->st_ctim.tv_sec && a->st_ctim.tv_nsec == b->st_ctim.tv_nsec;
}

static void request_close_fds(void)
{
    if (request.executable_fd >= 0) close(request.executable_fd);
    if (request.cwd_fd >= 0) close(request.cwd_fd);
    request.executable_fd = request.cwd_fd = -1;
}

static void request_free(void)
{
    request_close_fds();
    vector_free(&request.info);
    vector_free(&request.argv);
    vector_free(&request.environment);
    free(request.cwd);
    request = (struct approved_request){ .executable_fd = -1, .cwd_fd = -1 };
}

static int request_capture(char **info, char **argv)
{
    struct stat original;
    if (request.ready) { errno = EALREADY; return -1; }
    if (vector_copy(&request.info, info, 1) || vector_copy(&request.argv, argv, 0)) goto fail;
    const char *command = request_value("command"), *cwd = request_value("cwd");
    if (!command || command[0] != '/' || !request.argv.count || !request.argv.items[0][0] ||
        (cwd && cwd[0] != '/')) { errno = EINVAL; goto fail; }
    /* This first binding admits only an immutable native executable. Mutable
     * program inputs are not granted by retaining their argument strings. */
    request.executable_fd = immutable_fd(command);
    if (request.executable_fd < 0 || fstat(request.executable_fd, &request.executable)) goto fail;
    if (!(request.executable.st_mode & 0111)) { errno = EACCES; goto fail; }
    const char *fd_text = request_value("execfd");
    if (fd_text) {
        char *end;
        errno = 0;
        long fd = strtol(fd_text, &end, 10);
        if (!*fd_text || strspn(fd_text, "0123456789") != strlen(fd_text) ||
            errno || *end || fd < 3 || fd > INT32_MAX ||
            fstat((int)fd, &original) || !same_file(&original, &request.executable)) {
            errno = ESTALE;
            goto fail;
        }
    }
    request.cwd = cwd ? strdup(cwd) : getcwd(NULL, 0);
    if (!request.cwd) goto fail;
    if (strlen(request.cwd) > 4096) { errno = E2BIG; goto fail; }
    request.cwd_fd = open(request.cwd, O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (request.cwd_fd < 0 || fstat(request.cwd_fd, &request.directory)) goto fail;
    if (!S_ISDIR(request.directory.st_mode)) { errno = ENOTDIR; goto fail; }
    request.native_info = info;
    request.native_argv = argv;
    request.caller_uid = getuid();
    request.caller_gid = getgid();
    request.ready = 1;
    return 0;
fail:;
    int error = errno ? errno : EINVAL;
    request_free();
    errno = error;
    return -1;
}

static int request_finish(char **environment)
{
    struct stat executable, directory;
    int fd = -1, cwd = -1;
    if (!request.ready || request.session) { errno = EPERM; goto fail; }
    if (!vector_matches(&request.info, request.native_info) ||
        !vector_matches(&request.argv, request.native_argv)) { errno = ESTALE; goto fail; }
    fd = immutable_fd(request_value("command"));
    if (fd < 0 || fstat(fd, &executable) || !same_file(&request.executable, &executable)) {
        errno = ESTALE;
        goto fail;
    }
    cwd = open(request.cwd, O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (cwd < 0 || fstat(cwd, &directory) || directory.st_dev != request.directory.st_dev ||
        directory.st_ino != request.directory.st_ino) { errno = ESTALE; goto fail; }
    /* init_session may replace the environment; snapshot its FINAL output,
     * without changing native-owned memory or emitting any values. */
    if (vector_copy(&request.environment, environment, 1)) goto fail;
    close(fd);
    close(cwd);
    request_close_fds(); /* sudo closefrom must not create stale FD ownership. */
    request.session = 1;
    return 0;
fail:;
    int error = errno ? errno : EINVAL;
    if (fd >= 0) close(fd);
    if (cwd >= 0) close(cwd);
    request_close_fds();
    errno = error;
    return -1;
}

/* This callback is used only by the source-bound frontend, in its actual
 * command child. No request bytes, descriptor or authority cross an IPC API.
 * Claim before namespace entry; check final native env/UID setup afterward.
 * Neither stage authorizes requested-command execution. */
static int request_child(int phase, char *const environment[], uid_t uid, uid_t euid)
{
    struct stat ns, executable, directory;
    int fd = -1, cwd = -1;
    if (!request.session || stat("/proc/self/ns/pid", &ns)) goto fail;
    if (phase == 0) {
        if (request.child_attempted++) { errno = EALREADY; goto fail; }
        if (!vector_matches(&request.info, request.native_info) ||
            !vector_matches(&request.argv, request.native_argv)) { errno = ESTALE; goto fail; }
        fd = immutable_fd(request_value("command"));
        if (fd < 0 || fstat(fd, &executable) || !same_file(&executable, &request.executable)) {
            errno = ESTALE; goto fail;
        }
        cwd = open(request.cwd, O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (cwd < 0 || fstat(cwd, &directory) || directory.st_dev != request.directory.st_dev ||
            directory.st_ino != request.directory.st_ino) { errno = ESTALE; goto fail; }
        close(fd); close(cwd);
        request.child_pid = getpid();
        request.child_namespace = ns.st_ino;
        return 0;
    }
    if (phase != 1 || !request.child_pid || request.child_verified++ ||
        request.child_pid != getpid() || request.child_namespace != ns.st_ino ||
        !vector_matches(&request.environment, environment)) { errno = ESTALE; goto fail; }
    const char *keys[] = {"runas_uid", "runas_euid"};
    uid_t ids[] = {uid, euid};
    for (unsigned i = 0; i < 2; i++) {
        const char *value = request_value(keys[i]);
        if (!value && i == 1) value = request_value("runas_uid");
        char *end;
        errno = 0;
        unsigned long parsed = value ? strtoul(value, &end, 10) : 0;
        if (!value || !*value || strspn(value, "0123456789") != strlen(value) ||
            errno || *end || parsed != ids[i]) { errno = ESTALE; goto fail; }
    }
    if (getuid() != uid || geteuid() != euid) { errno = EPERM; goto fail; }
    return 0;
fail:;
    int error = errno ? errno : EPERM;
    request.child_pid = 0; /* A failed/replayed handoff is never reusable. */
    if (fd >= 0) close(fd);
    if (cwd >= 0) close(cwd);
    errno = error;
    return -1;
}
