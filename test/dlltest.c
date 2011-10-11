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

#define HP_DLLTEST(D,L) \
do { \
	time_t tt = time(NULL); \
	FILE *ff = fopen("/tmp/hotpatchtest.log", "a"); \
	if (ff) { \
		fprintf(ff, "Dll opened. %s\n", ctime(&tt)); \
		if (L > 0) \
			fprintf(ff, "Data: %s Len: "LU"\n", (char *)D, (size_t)L); \
		fclose(ff); \
	} \
} while (0)

void _init()
{
	HP_DLLTEST(__func__, 0);
}

int mysym(char *data, size_t len)
{
	HP_DLLTEST(data, len);
	return 0xDEADBEEF;
}
