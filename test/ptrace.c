/*
 * hotpatch is a dll injection strategy.
 * Copyright (c) 2010-2011, Vikas Naresh Kumar, Selective Intellect LLC
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright
 *	 notice, this list of conditions and the following disclaimer in the
 *	 documentation and/or other materials provided with the distribution.
 *
 * * Neither the name of Selective Intellect LLC nor the
 *   names of its contributors may be used to endorse or promote products
 *   derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#include <hotpatch_config.h>
#ifdef HOTPATCH_HAS_ASSERT_H
	#undef NDEBUG
	#include <assert.h>
#endif

int test_child(pid_t pid)
{
	int st = 0;
	int memfd = -1;
	char procfile[4096];
	memset(procfile, 0, sizeof(procfile));
	sprintf(procfile, "/proc/%d/maps", pid);
	printf("Trying to open %s\n", procfile);
	memfd = open(procfile, O_RDONLY);
	assert(memfd >= 0);
	memset(procfile, 0, sizeof(procfile));
	while ((st = read(memfd, procfile, sizeof(procfile))) >= 0) {
		printf("st: %d\n", st);
		printf("%s\n", procfile);
		if (st == 0) break;
	}
	if (st < 0) {
		st = errno;
		printf("error: %s\n", strerror(st));
	}
    close(memfd);
	return st;
}

int main(int argc, char **argv, char **envp)
{
	pid_t pid = 0;
	int status = 0;
	assert(argc >= 2);
	pid = (pid_t)strtol(argv[1], NULL, 10);
	assert(pid > 0);
	
	assert(ptrace(PTRACE_ATTACH, pid, NULL, NULL) == 0);

	while (1) {
		struct user *cldata = NULL;
		long retval = 0;
		waitpid(-1, &status, 0);
		if (WIFEXITED(status) || WIFSIGNALED(status)) {
			break;
		}
		cldata = malloc(sizeof(*cldata));
		if (!cldata) {
			fprintf(stderr, "Out of memory. Tried to allocate "LU"\n", sizeof(*cldata));
			break;
		}
		memset(cldata, 0, sizeof(*cldata));
		if (ptrace(PTRACE_GETREGS, pid, NULL, cldata) < 0) {
			int err = errno;
			printf("[%s:%d] Error: %s\n", __func__, __LINE__, strerror(err));
		} else {
			printf("R15: %p\n", (void *)cldata->regs.r15);
			printf("R14: %p\n", (void *)cldata->regs.r14);
			printf("R13: %p\n", (void *)cldata->regs.r13);
			printf("R12: %p\n", (void *)cldata->regs.r12);
			printf("RBP: %p\n", (void *)cldata->regs.rbp);
			printf("RBX: %p\n", (void *)cldata->regs.rbx);
			printf("R11: %p\n", (void *)cldata->regs.r11);
			printf("R10: %p\n", (void *)cldata->regs.r10);
			printf("R9: %p\n", (void *)cldata->regs.r9);
			printf("R8: %p\n", (void *)cldata->regs.r8);
			printf("RAX: %p\n", (void *)cldata->regs.rax);
			printf("RCX: %p\n", (void *)cldata->regs.rcx);
			printf("RDX: %p\n", (void *)cldata->regs.rdx);
			printf("RSI: %p\n", (void *)cldata->regs.rsi);
			printf("RDI: %p\n", (void *)cldata->regs.rdi);
			printf("ORIG_RAX: %p\n", (void *)cldata->regs.orig_rax);
			printf("RIP: %p\n", (void *)cldata->regs.rip);
			printf("CS: %p\n", (void *)cldata->regs.cs);
			printf("EFLAGS: %p\n", (void *)cldata->regs.eflags);
			printf("RSP: %p\n", (void *)cldata->regs.rsp);
			printf("SS: %p\n", (void *)cldata->regs.ss);
			printf("FS_BASE: %p\n", (void *)cldata->regs.fs_base);
			printf("GS_BASE: %p\n", (void *)cldata->regs.gs_base);
			printf("DS: %p\n", (void *)cldata->regs.ds);
			printf("ES: %p\n", (void *)cldata->regs.es);
			printf("FS: %p\n", (void *)cldata->regs.fs);
			printf("GS: %p\n", (void *)cldata->regs.gs);
			printf("FPVALID: %d\n", cldata->u_fpvalid);
			printf("TSize: "LU"\n", cldata->u_tsize);
			printf("DSize: "LU"\n", cldata->u_dsize);
			printf("SSize: "LU"\n", cldata->u_ssize);
			printf("Start code: %p\n", (void *)cldata->start_code);
			printf("Start stack: %p\n", (void *)cldata->start_stack);
			printf("Signal: "LU"\n", cldata->signal);
			printf("Reserved: %d\n", cldata->reserved);
			printf("AR0: %p\n", (void *)cldata->u_ar0);
			printf("FPSTATE: %p\n", (void *)cldata->u_fpstate);
			printf("MAGIC: "LU"\n", cldata->magic);
			printf("U_COMM: %s\n", cldata->u_comm);
		}
		cldata->regs.orig_rax++;
		ptrace(PTRACE_SETREGS, pid, NULL, cldata);
		if ((retval = ptrace(PTRACE_PEEKUSER, pid, offsetof(struct user, u_fpvalid), NULL)) < 0) {
			int err = errno;
			printf("[%s:%d] Return value: "LU" Error: %s\n", __func__, __LINE__, retval, strerror(err));
		} else {
			cldata->start_code = retval;
			printf("Start code: %p\n", (void *)cldata->start_code);
		}
		retval = ptrace(PTRACE_PEEKTEXT, pid, cldata->regs.rip, NULL);
		printf("[%s:%d] Return value: "LU". \n", __func__, __LINE__, retval);
        if (argc > 2) {
            ptrace(PTRACE_CONT, pid, 0, 0);
        }
		printf("[%s:%d] \n", __func__, __LINE__);
		free(cldata);
		if (test_child(pid) < 0) {
			break;
		}
	}
	assert(ptrace(PTRACE_DETACH, pid, NULL, NULL) == 0);
	return 0;
}
