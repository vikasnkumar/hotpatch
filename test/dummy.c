#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>

int main()
{
	while (1) {
		struct timeval tv = { 0 };
		sleep(2);
		gettimeofday(&tv, NULL);
		printf("Working %ld.%ld\n", tv.tv_sec, tv.tv_usec);
	}
	return 0;
}
