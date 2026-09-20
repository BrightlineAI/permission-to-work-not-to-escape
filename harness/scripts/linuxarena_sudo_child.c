/* Trusted sudo command-child checkpoint, pinned Linux x86_64 only.
 * The source-patched frontend calls this AFTER native group/limit/chroot setup
 * and BEFORE native setresuid. Authentication and terminal monitors never call
 * it. This milestone still redirects every approved command to the closed gate.
 * Capability/filter reduction alone is NOT filesystem/process confinement.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <linux/capability.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/fsuid.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "linuxarena_sudo_child.h"
/* Generated from linuxarena_namespace.py, never a second hand-written filter. */
#include "linuxarena_sudo_filter.h"

#if !defined(__linux__) || !defined(__x86_64__) || defined(__ILP32__)
#error Unsupported sudo child checkpoint architecture
#endif

/* Exact Docker-default setup set for this closed fixture; not a payload grant.
 * A future namespace setup must bind its own starting set explicitly. */
#define PTW_SETUP_MASK UINT64_C(0xa80425fb)
struct caps { uint64_t effective, permitted, inheritable, bounding, ambient; };
static gid_t groups[256], rgid, egid, sgid;
static int ngroups, prepared;
static uid_t target;

static int reject(const char *stage)
{
    int error = errno ? errno : EPERM;
    fprintf(stderr, "PTW_CHILD_REJECT stage=%s errno=%d\n", stage, error);
    errno = error;
    return -1;
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
    if (ptw_child_observe()) return -1;
    prepared = 0;
    return 0;
}
