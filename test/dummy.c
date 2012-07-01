#ifndef _GNU_SOURCE
	#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <sys/syscall.h>
#if __WORDSIZE == 64
	#define LX "%lx"
	#define LU "%lu"
#else
	#define LX "%x"
	#define LU "%u"
#endif

static int counter = 0;
void myfun()
{
	printf("%d: I am here in %s on %d\n", counter++,
		   __func__, __LINE__);
	if (counter >= INT32_MAX)
		counter = 0;
}

int main()
{
	intptr_t here0 = 0;
	intptr_t here1 = 0;
	const char *str = "Hello World!";
	size_t len = strlen(str);
	here0 = (intptr_t)syscall(SYS_brk, 0);
	here1 = (intptr_t)syscall(SYS_brk, here0 + len + 1);
	printf("Starting dummy 0x"LX" 0x"LX"\n", here0, here1);
	memcpy((void *)here0, str, len + 1);
	printf("String: %s\n", (const char *)here0);
	syscall(SYS_brk, here0);
	while (1) {
		struct timeval tv = { 0 };
		sleep(2);
		gettimeofday(&tv, NULL);
		printf("Working "LU"."LU"\n", (size_t)tv.tv_sec, (size_t)tv.tv_usec);
		myfun();
	}
	printf("Stopping dummy\n");
	return 0;
}
