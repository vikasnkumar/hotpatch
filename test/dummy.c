#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>

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
	printf("Starting dummy\n");
	while (1) {
		struct timeval tv = { 0 };
		sleep(2);
		gettimeofday(&tv, NULL);
		printf("Working %ld.%ld\n", tv.tv_sec, tv.tv_usec);
		myfun();
	}
	printf("Stopping dummy\n");
	return 0;
}
