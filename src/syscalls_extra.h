// This file contains additional syscall's that aren't implemented by dietlibc yet (only supported on x86_64 linux sorry)
// See the original file here that contains already implemented syscalls https://github.com/ensc/dietlibc/blob/master/x86_64/syscalls.h

#define __NR_execveat 322

#if defined(__PIE__)

#define syscall_weak(name,wsym,sym) \
.text; \
.type wsym,@function; \
.weak wsym; \
.hidden wsym; \
wsym: ; \
.type sym,@function; \
.global sym; \
.hidden sym; \
sym: \
.ifge __NR_##name-256 ; \
	mov	$__NR_##name,%ax; \
	jmp	__unified_syscall_16bit@PLT;  \
.else ; \
	mov	$__NR_##name,%al; \
	jmp	__unified_syscall@PLT; \
.endif

#define syscall(name,sym) \
.text; \
.type sym,@function; \
.global sym; \
.hidden sym; \
sym: \
.ifge __NR_##name-256 ; \
	mov	$__NR_##name,%ax; \
	jmp	__unified_syscall_16bit@PLT; \
.else ; \
	mov	$__NR_##name,%al; \
	jmp	__unified_syscall@PLT; \
.endif

#elif defined(__PIC__)

#define syscall_weak(name,wsym,sym) \
.text; \
.type wsym,@function; \
.weak wsym; \
wsym: ; \
.type sym,@function; \
.global sym; \
sym: \
.ifge __NR_##name-256 ; \
	mov	$__NR_##name,%ax; \
	jmp	__unified_syscall_16bit@PLT;  \
.else ; \
	mov	$__NR_##name,%al; \
	jmp	__unified_syscall@PLT; \
.endif

#define syscall(name,sym) \
.text; \
.type sym,@function; \
.global sym; \
sym: \
.ifge __NR_##name-256 ; \
	mov	$__NR_##name,%ax; \
	jmp	__unified_syscall_16bit@PLT; \
.else ; \
	mov	$__NR_##name,%al; \
	jmp	__unified_syscall@PLT; \
.endif

#else

#define syscall_weak(name,wsym,sym) \
.text; \
.type wsym,@function; \
.weak wsym; \
wsym: ; \
.type sym,@function; \
.global sym; \
sym: \
.ifge __NR_##name-256 ; \
	mov	$__NR_##name,%ax; \
	jmp	__unified_syscall_16bit; \
.else ; \
	mov	$__NR_##name,%al; \
	jmp	__unified_syscall; \
.endif

#define syscall(name,sym) \
.text; \
.type sym,@function; \
.global sym; \
sym: \
.ifge __NR_##name-256 ; \
	mov	$__NR_##name,%ax; \
	jmp	__unified_syscall_16bit; \
.else ; \
	mov	$__NR_##name,%al; \
	jmp	__unified_syscall; \
.endif
#endif
