#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"

static void syscall_handler (struct intr_frame *);

struct list process_info_list;
static struct lock pil_lock;


struct process_info* get_process_info(tid_t pid) {
  struct list_elem *e;

  struct process_info* pi = NULL;
  lock_acquire(&pil_lock);
  for (e = list_begin (&process_info_list); e != list_end (&process_info_list);
       e = list_next (e))
  {
      struct process_info *p = list_entry (e, struct process_info, elem);
      if (p->pid == pid) {
        pi = p;
        break;
      }
  }

  lock_release(&pil_lock);

  return pi;
}


void add_process_to_list(const char* name, tid_t tid) {
  struct process_info *pi  = (struct process_info*) malloc (sizeof(struct process_info));
  pi->exit_code = -1000;
  pi->pid = tid;
  memcpy(pi->name, name, strlen(name)+1);

  lock_acquire(&pil_lock);
  list_push_back(&process_info_list, &pi->elem);
  lock_release(&pil_lock);
}

void set_process_exitcode(tid_t pid, int exit_code) {
  struct list_elem *e;

  lock_acquire(&pil_lock);

  for (e = list_begin (&process_info_list); e != list_end (&process_info_list);
       e = list_next (e))
    {
      struct process_info *p = list_entry (e, struct process_info, elem);
      if (p->pid == pid) {
        p->exit_code = exit_code;
        break;
      }
    }

  lock_release(&pil_lock);
}

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  list_init(&process_info_list);
  lock_init(&pil_lock);
}

bool check_ptr(void* ptr) {
  struct thread* t = thread_current();
  if ( !is_user_vaddr (ptr) || pagedir_get_page(t->pagedir, ptr) == NULL) {
    return false;
  }
  return true;
}

void exit(int exit_code) {  
  set_process_exitcode(thread_current()->tid, exit_code);
  struct process_info* pi = get_process_info(thread_current()->tid) ;
  
  printf("%s: exit(%d)\n", pi->name , exit_code);
  thread_exit();
}

void create(struct intr_frame *f, int* esp) {
  if ( !check_ptr(esp+1) || !check_ptr(esp+2) ) {
    exit(-1);
    return;
  }
  if (!check_ptr((void*)(*(esp + 1))) ){
    exit(-1);
    return;
  }

  char* buffer = *(esp + 1);
  unsigned int size = *(esp + 2);
  if (strlen(buffer) < 1) {
    f->eax = 0;
    return;
  }
  
  f->eax = filesys_create(buffer, size);
}

void remove(struct intr_frame *f, int* esp){
  if ( !check_ptr(esp+1) ) {
    f->eax = false;
    exit(-1);
  }
  if (!check_ptr((void*)(*(esp + 1))) ){
    f->eax = false;
    exit(-1);
  }
  
  char* name = *(esp + 1);

  f->eax = filesys_remove(name);
}

void open(struct intr_frame *f, int* esp){
  if ( !check_ptr(esp+1) ) {
    f->eax = -1;
    exit(-1);
  }
  if (!check_ptr((void*)(*(esp + 1))) ){
    f->eax = -1;
    exit(-1);
  }
  
  char* name = *(esp + 1);
    
  if (strlen(name) < 1) {
    f->eax = -1;
    return;
  }
  
  struct file *file = filesys_open(name);
  
  if(file == NULL){
    f->eax = -1;
    return;
  }
  
  struct file_desc *new = (struct file_desc*) malloc (sizeof(struct file_desc));
  
  new->file = file;
  new->file_id = ++(thread_current()->cur_descripters);

  f->eax = new->file_id;
  
  list_push_back(&thread_current()->file_list, &new->elem);
}

void close(struct intr_frame *f, int* esp){

  if ( !check_ptr(esp+1) ) {
    exit(-1);
  }

  int file_close = *(esp + 1);

  if(file_close < 100){
    exit(-1);
  }

  struct list_elem *e;
	for (e = list_begin (&thread_current()->file_list); e != list_end (&thread_current()->file_list); e = list_next (e)){
    struct file_desc *fd = list_entry (e, struct file_desc, elem);
    if(fd->file_id == file_close){
      list_remove(&fd->elem);
      free(fd);
      break;
    }
  }

}

void write(struct intr_frame *f, int* esp) {
  if ( !check_ptr(esp+1) || !check_ptr(esp+2) || !check_ptr(esp+3) ) {
    exit(-1);
    return;
  }

  int fd = *(esp + 1);
  void* buffer = *(esp + 2);
  unsigned int len = *(esp + 3);

  if (!check_ptr( buffer )){
    exit(-1);
    return;
  }

  if (fd == STDIN_FILENO) {
    exit(-1);
    return;
  }
  else if (fd == STDOUT_FILENO) {
    putbuf(buffer, len);
    f->eax = len;
  }
  else {
    if(len < 1){
      f->eax = 0;
      return;
    }
    
    struct list_elem *e;
		
	  for (e = list_begin (&thread_current()->file_list); e != list_end (&thread_current()->file_list); e = list_next (e)){
      struct file_desc *file_d = list_entry (e, struct file_desc, elem);
      if(file_d->file_id == fd){
        f->eax = file_write(file_d->file,buffer,len);
        break;
      }
    }
  }
}

void filesize(struct intr_frame *f, int* esp){
  if ( !check_ptr(esp+1) ) {
    exit(-1);
    return;
  }
  int fd = *(esp + 1);
  
  struct list_elem *e;
		
  for (e = list_begin (&thread_current()->file_list); e != list_end (&thread_current()->file_list); e = list_next (e)){
    struct file_desc *file_d = list_entry (e, struct file_desc, elem);
    if(file_d->file_id == fd){
      f->eax = file_length(file_d->file);
      break;
    }
  }
}

void read(struct intr_frame *f, int* esp) {
  if ( !check_ptr(esp+1) || !check_ptr(esp+2) || !check_ptr(esp+3) ) {
    exit(-1);
    return;
  }

  int fd = *(esp + 1);
  void* buffer = *(esp + 2);
  unsigned int len = *(esp + 3);

  if (!check_ptr( buffer )){
    exit(-1);
    return;
  }
  if(len < 1){
      f->eax = 0;
      return;
  }
  if (fd == STDIN_FILENO) {
    int i;
    for (i = 0; i != len; ++i) {
      *(uint8_t *)(buffer + i) = input_getc();
    }
    f->eax = len;
    return;
  }
  else if (fd == STDOUT_FILENO) {
    exit(-1);
    return;
  }
  else {    
    struct list_elem *e;
		
	  for (e = list_begin (&thread_current()->file_list); e != list_end (&thread_current()->file_list); e = list_next (e)){
      struct file_desc *file_d = list_entry (e, struct file_desc, elem);
      if(file_d->file_id == fd){
        f->eax = file_read(file_d->file,buffer,len);
        return;
      }
    }
  }
}

void seek(struct intr_frame *f, int* esp){
  if ( !check_ptr(esp+1) || !check_ptr(esp+2) ) {
    exit(-1);
    return;
  }

  int fd = *(esp + 1);
  unsigned int pos = *(esp + 2);

  if(pos < 0){
      return;
  }
  
  struct list_elem *e;
		
  for (e = list_begin (&thread_current()->file_list); e != list_end (&thread_current()->file_list); e = list_next (e)){
    struct file_desc *file_d = list_entry (e, struct file_desc, elem);
    if(file_d->file_id == fd){
      file_seek(file_d->file, pos);
      return;
    }
  }
}

void tell(struct intr_frame *f, int* esp){
  if ( !check_ptr(esp+1) ) {
    exit(-1);
    return;
  }

  int fd = *(esp + 1);
  
  struct list_elem *e;
		
  for (e = list_begin (&thread_current()->file_list); e != list_end (&thread_current()->file_list); e = list_next (e)){
    struct file_desc *file_d = list_entry (e, struct file_desc, elem);
    if(file_d->file_id == fd){
      f->eax = (int) file_tell(file_d->file);
      return;
    }
  }
  
  f->eax = -1;
}

void exec(struct intr_frame *f, int* esp) {
  if ( !check_ptr(esp+1) ) {
    exit(-1);
    return;
  }
  if (!check_ptr((void*)(*(esp + 1))) ){
    f->eax = -1;
    exit(-1);
  }
  
  char* name = *(esp + 1);
  
  if (strlen(name) == 0) {
    f->eax = -1;
    return;
  }
  
  char *save_ptr1;
  char* filename_copy = palloc_get_page(0);
  strlcpy (filename_copy, name, PGSIZE);
  char *exename = strtok_r (filename_copy, " ", &save_ptr1);
  struct file *file = filesys_open(exename);
  if(file == NULL){
    f->eax = -1;
    return;
  }
  
  f->eax = process_execute(name);
}

void wait(struct intr_frame *f, int* esp) {
  if ( !check_ptr(esp+1) ) {
    exit(-1);
    return;
  }
  
  tid_t tid = *(esp + 1);
  
  f->eax = process_wait(tid);
}

static void
syscall_handler (struct intr_frame *f)
{
  int* esp = f->esp;
 
  if ( !check_ptr(esp)) {
    exit(-1);
    return;
  }

  int number = *esp;
  if (number == 0) {
    shutdown_power_off();
  }
  else if (number == 1) {
    if ( !check_ptr(esp+1) ) {
      exit(-1);
      return;
    }
    int exit_code = *(esp+1) ;
    exit(exit_code);
  }
  else if (number == SYS_WRITE) {
    write(f, esp);
  }
  else if (number == SYS_CREATE) {
    create(f, esp);
  }
  else if (number == SYS_REMOVE) {
    remove(f, esp);
  }
  else if (number == SYS_OPEN) {
    open(f,esp);
  }
  else if (number == SYS_CLOSE) {
    close(f,esp);
  }
  else if (number == SYS_READ) {
    read(f, esp);
  }
  else if (number == SYS_FILESIZE) {
    filesize(f, esp);
  }
  else if (number == SYS_SEEK) {
    seek(f, esp);
  }
  else if (number == SYS_TELL) {
    tell(f, esp);
  }
  else if (number == SYS_WAIT) {
    wait(f, esp);
  }
  else if (number == SYS_EXEC) {
    exec(f, esp);
  }

}