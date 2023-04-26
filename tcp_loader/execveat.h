#ifndef __EXECVEAT_H__
#define __EXECVEAT_H__

// Enable the execveat to call the execveat syscall - using dietlibc's weird method of assembly defined syscalls
// https://man7.org/linux/man-pages/man2/execveat.2.html
int execveat (int dirfd, const char *pathname, const char *const argv[], const char *const envp[], int flags);

#endif
