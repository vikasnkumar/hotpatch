#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>

int main()
{
	printf("Starting dummy\n");
	while (1) {
		struct timeval tv = { 0 };
		sleep(2);
		gettimeofday(&tv, NULL);
		printf("Working %ld.%ld\n", tv.tv_sec, tv.tv_usec);
	}
	printf("Stopping dummy\n");
	return 0;
}
