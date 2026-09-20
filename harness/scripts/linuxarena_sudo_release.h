/* One bounded argv handoff between immutable static stages. This is data, not
 * authority: neither stage gains privileges, and only native child admission
 * constructs the pending argv. No auth or old-root FD crosses an exec. */
#include <stdint.h>

#define PTW_RELEASE_MAX 528
#define PTW_RELEASE_BYTES 270336
#ifndef PTW_CLOSED_HELPER
static int release_option_supported(const char *entry)
{
    /* Native noexec adds LD_PRELOAD only at sudo_execve, after the session
     * snapshot. A static intermediary cannot preserve that enforcement.
     * Refuse it, descriptor inheritance and alternate execution domains. */
    const char *prefixes[] = {"noexec=", "preserve_fds=", "selinux_role=", "selinux_type=",
                             "exec_background="};
    for (unsigned i = 0; i < sizeof(prefixes) / sizeof(prefixes[0]); i++) {
        size_t n = strlen(prefixes[i]);
        if (!strncmp(entry, prefixes[i], n))
            return (i == 0 || i == 4) && !strcmp(entry + n, "false");
    }
    return 1;
}
#endif
static int release_identity(char out[384], const struct stat *st, int directory)
{
    int n = directory ? snprintf(out, 384, "%llu:%llu",
        (unsigned long long)st->st_dev, (unsigned long long)st->st_ino) :
        snprintf(out, 384, "%llu:%llu:%llu:%llu:%llu:%lld:%lld:%ld:%lld:%ld",
        (unsigned long long)st->st_dev, (unsigned long long)st->st_ino,
        (unsigned long long)st->st_mode, (unsigned long long)st->st_uid,
        (unsigned long long)st->st_gid, (long long)st->st_size,
        (long long)st->st_mtim.tv_sec, st->st_mtim.tv_nsec,
        (long long)st->st_ctim.tv_sec, st->st_ctim.tv_nsec);
    if (n <= 0 || n >= 384) { errno = EOVERFLOW; return -1; }
    return 0;
}

#ifdef PTW_CLOSED_HELPER
struct release_view { char *command, *cwd, *executable, *directory; char **env, **args; };

static int release_parse(int argc, char **argv, struct release_view *out)
{
    if (argc < 9 || argc > PTW_RELEASE_MAX ||
        (strcmp(argv[1], "--pending") && strcmp(argv[1], "--confined")) ||
        argv[2][0] != '/' || argv[3][0] != '/') { errno = EINVAL; return -1; }
    size_t bytes = 0;
    for (int i = 0; i < argc; i++) {
        size_t size = strnlen(argv[i], PTW_RELEASE_BYTES);
        if (size == PTW_RELEASE_BYTES || size + 1 > PTW_RELEASE_BYTES - bytes) {
            errno = E2BIG; return -1;
        }
        bytes += size + 1;
    }
    char *end;
    errno = 0;
    unsigned long count = strtoul(argv[6], &end, 10);
    if (errno || !*argv[6] || strspn(argv[6], "0123456789") != strlen(argv[6]) ||
        *end || count > 256 || 8 + count >= (unsigned)argc || *argv[7 + count] ||
        !*argv[8 + count] || argc - (8 + count) > 256) { errno = EINVAL; return -1; }
    for (unsigned i = 0; i < count; i++) {
        char *entry = argv[7 + i], *equals = strchr(entry, '=');
        if (!equals || equals == entry) { errno = EINVAL; return -1; }
        size_t key = equals - entry;
        for (unsigned j = 0; j < i; j++)
            if (!strncmp(entry, argv[7 + j], key) && argv[7 + j][key] == '=') {
                errno = EINVAL; return -1;
            }
    }
    *out = (struct release_view){argv[2], argv[3], argv[4], argv[5],
                               &argv[7], &argv[8 + count]};
    return 0;
}

static int release_bind(const struct release_view *view)
{
    struct stat st;
    struct statvfs fs;
    char identity[384];
    int fd = open(view->command, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return -1;
    if (fstat(fd, &st) || fstatvfs(fd, &fs) || !S_ISREG(st.st_mode) ||
        st.st_uid || (st.st_mode & 0022) || !(st.st_mode & 0111) ||
        !(fs.f_flag & ST_RDONLY) || release_identity(identity, &st, 0) ||
        strcmp(identity, view->executable)) goto fail;
    /* Only native immutable ELF executables in this bounded seam. A script
     * needs an explicit interpreter request; never preserve an executable FD
     * across exec merely to make shebang fallback work. */
    unsigned char magic[4];
    if (pread(fd, magic, 4, 0) != 4 || memcmp(magic, "\177ELF", 4)) goto fail;
    if (chdir(view->cwd) || stat(".", &st) || release_identity(identity, &st, 1) ||
        strcmp(identity, view->directory)) goto fail;
    return fd;
fail:;
    int error = errno ? errno : ESTALE;
    close(fd); errno = error; return -1;
}
#endif
