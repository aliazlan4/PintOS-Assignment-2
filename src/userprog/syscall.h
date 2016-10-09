#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/thread.h"

struct process_info {
  tid_t pid;
  char name[256];
  int exit_code;

  struct list_elem elem;
};

void set_process_exitcode(tid_t pid, int exitcode) ;
struct process_info* get_process_info(tid_t pid) ;
void add_process_to_list(const char* name,  tid_t tid) ;


void syscall_init (void);

#endif /* userprog/syscall.h */
