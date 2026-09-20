/* Image-specific sudo execution checkpoint. No command-release interface. */
#ifndef PTW_SUDO_CHILD_H
#define PTW_SUDO_CHILD_H
#include <sys/types.h>
int ptw_child_before_uid(uid_t, uid_t);
int ptw_child_after_uid(uid_t, uid_t);
int ptw_child_observe(void);
#endif
