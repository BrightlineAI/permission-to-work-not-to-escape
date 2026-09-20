/* Image-specific sudo execution checkpoint. No command-release interface. */
#ifndef PTW_SUDO_CHILD_H
#define PTW_SUDO_CHILD_H
#include <sys/types.h>
int ptw_child_pin(void);
int ptw_child_request_pin(void);
int ptw_child_request_verify(char *const [], uid_t, uid_t);
int ptw_child_barrier_fd(void);
void ptw_child_cleanup(void);
/* route: 0 = pipe command child, 1 = PTY monitor's command child. */
pid_t ptw_child_fork(pid_t (*)(void), int);
/* PTY parent calls after foreground assignment, before unmask/event dispatch. */
int ptw_child_continue(pid_t);
/* Bounded numeric job-control diagnostics; no authority or signal changes. */
void ptw_job_trace(int, pid_t, pid_t, int, int, int, int);
int ptw_job_killpg(int, pid_t, int, int);
void ptw_job_wait_observe(pid_t, int);
int ptw_child_exec_observe(void);
int ptw_child_descriptors(void);
int ptw_child_placement_effect(void);
int ptw_child_before_uid(uid_t, uid_t);
int ptw_child_after_uid(uid_t, uid_t);
int ptw_child_observe(void);
#endif
