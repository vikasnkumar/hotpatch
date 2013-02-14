### hotpatch is a dll injection strategy
### Copyright (c) 2010-2011, Vikas Naresh Kumar, Selective Intellect LLC
### All rights reserved.
### 
### Redistribution and use in source and binary forms, with or without
### modification, are permitted provided that the following conditions are met:
### 
###     * Redistributions of source code must retain the above copyright
###       notice, this list of conditions and the following disclaimer.
### 
###     * Redistributions in binary form must reproduce the above copyright
###       notice, this list of conditions and the following disclaimer in the
###       documentation and/or other materials provided with the distribution.
### 
###     * Neither the name of Selective Intellect LLC nor the
###       names of its contributors may be used to endorse or promote products
###       derived from this software without specific prior written permission.
### 
### THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
### ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
### WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
### DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
### DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
### (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
### LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
### ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
### (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
### SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
### 
cmake_minimum_required(VERSION 2.6 FATAL_ERROR)

option(DEBUG "In Debug mode" ON)
option(USE_ASM "Use Assembler" OFF)
option(BUILD_HOTPATCHER "Build hotpatcher" ON)
option(BUILD_TESTS "Build tests" ON)
if (NOT CMAKE_BUILD_TYPE STREQUAL "Debug")
	set(DEBUG OFF)
endif (NOT CMAKE_BUILD_TYPE STREQUAL "Debug")

if (CMAKE_COMPILER_IS_GNUCC)
	if (ARCH)
		if (ARCH STREQUAL "x86_64")
			message(STATUS "Compiling for ${ARCH} 64-bit")
			set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -m64")
			set(CMAKE_CXX_FLAGS "${CMAKE_C_FLAGS} -m64")
		else (ARCH STREQUAL "x86_64")
			message(STATUS "Compiling for ${ARCH} 32-bit")
			set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -m32")
			set(CMAKE_CXX_FLAGS "${CMAKE_C_FLAGS} -m32")
		endif (ARCH STREQUAL "x86_64")
	endif (ARCH)
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -fPIC -pedantic -ansi -posix")
	set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -O0 -fno-inline")
	set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -O2")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -fPIC -pedantic -ansi -posix")
	set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -O0 -fno-inline")
	set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O2")
endif (CMAKE_COMPILER_IS_GNUCC)
include(CTest)
include(CheckFunctionExists)
include(CheckIncludeFile)
include(CheckIncludeFiles)
include(CheckSymbolExists)
include(CheckTypeSize)
if (WIN32 OR APPLE)
	message(FATAL_ERROR "Windows or Mac OSX is not supported")
endif (WIN32 OR APPLE)
check_include_file("features.h" HOTPATCH_HAS_FEATURES_H)
check_include_file("errno.h" HOTPATCH_HAS_ERRNO_H)
check_include_file("stdio.h" HOTPATCH_HAS_STDIO_H)
check_include_file("stdlib.h" HOTPATCH_HAS_STDLIB_H)
check_include_file("string.h" HOTPATCH_HAS_STRING_H)
check_function_exists("strnlen" HOTPATCH_HAS_STRNLEN_FN)
check_function_exists("strtok_r" HOTPATCH_HAS_STRTOKR_FN)
check_include_file("stddef.h" HOTPATCH_HAS_STDDEF_H)
check_include_file("stdint.h" HOTPATCH_HAS_STDINT_H)
check_include_file("stdarg.h" HOTPATCH_HAS_STDARG_H)
check_include_file("stdbool.h" HOTPATCH_HAS_STDBOOL_H)
check_include_file("time.h" HOTPATCH_HAS_TIME_H)
check_include_file("sys/time.h" HOTPATCH_HAS_SYS_TIME_H)
check_include_file("sys/types.h" HOTPATCH_HAS_SYS_TYPES_H)
check_include_file("unistd.h" HOTPATCH_HAS_UNISTD_H)
check_include_file("assert.h" HOTPATCH_HAS_ASSERT_H)
check_include_file("limits.h" HOTPATCH_HAS_LIMITS_H)
if (UNIX AND ${CMAKE_SYSTEM_NAME} STREQUAL "Linux")
	check_include_file("elf.h" HOTPATCH_HAS_LINUX_ELF_H)
	check_include_file("dlfcn.h" HOTPATCH_HAS_LINUX_DLFCN_H)
	if (HOTPATCH_HAS_LINUX_DLFCN_H)
		set(HOTPATCH_OTHER_LIBS ${HOTPATCH_OTHER_LIBS} dl)
	endif (HOTPATCH_HAS_LINUX_DLFCN_H)
	check_include_file("link.h" HOTPATCH_HAS_LINUX_LINK_H)
	check_include_file("pthread.h" HOTPATCH_HAS_LINUX_PTHREAD_H)
	if (HOTPATCH_HAS_LINUX_PTHREAD_H)
		set(HOTPATCH_OTHER_LIBS ${HOTPATCH_OTHER_LIBS} pthread)
	endif (HOTPATCH_HAS_LINUX_PTHREAD_H)
	check_include_file("setjmp.h" HOTPATCH_HAS_LINUX_SETJMP_H)
	check_include_file("signal.h" HOTPATCH_HAS_LINUX_SIGNAL_H)
	check_include_file("sys/ptrace.h" HOTPATCH_HAS_LINUX_SYS_PTRACE_H)
	check_include_file("sys/wait.h" HOTPATCH_HAS_LINUX_SYS_WAIT_H)
	check_include_file("sys/stat.h" HOTPATCH_HAS_LINUX_SYS_STAT_H)
	check_include_file("fcntl.h" HOTPATCH_HAS_LINUX_FCNTL_H)
	check_include_file("sys/syscall.h" HOTPATCH_HAS_LINUX_SYS_SYSCALL_H)
	check_include_files("sys/types.h;sys/user.h" HOTPATCH_HAS_LINUX_SYS_USER_H)
	check_function_exists("dl_iterate_phdr" HOTPATCH_HAS_LINUX_DLITERPHDR_FN)
	check_type_size("void *" HOTPATCH_VOIDPTR_SIZE) 
	if (NOT HAVE_HOTPATCH_VOIDPTR_SIZE)
		message(FATAL_ERROR "(void *) does not seem to be supported.")
	endif (NOT HAVE_HOTPATCH_VOIDPTR_SIZE)
	## Find assemblers
	if (USE_ASM)
	include(FindPerl)
	find_file(HOTPATCH_NASM nasm)
	if (HOTPATCH_NASM MATCHES "-NOTFOUND")
		message(STATUS "Found nasm - not found")
		set(HOTPATCH_HAS_NASM 0)
	else (HOTPATCH_NASM MATCHES "-NOTFOUND")
		message(STATUS "Found nasm - ${HOTPATCH_NASM}")
		set(HOTPATCH_HAS_NASM 1)
	endif (HOTPATCH_NASM MATCHES "-NOTFOUND")
	find_file(HOTPATCH_YASM yasm)
	if (HOTPATCH_YASM MATCHES "-NOTFOUND")
		message(STATUS "Found yasm - no")
		set(HOTPATCH_HAS_YASM 1)
	else (HOTPATCH_YASM MATCHES "-NOTFOUND")
		message(STATUS "Found yasm - ${HOTPATCH_YASM}")
		set(HOTPATCH_HAS_YASM 1)
	endif (HOTPATCH_YASM MATCHES "-NOTFOUND")
	if (HOTPATCH_HAS_NASM OR HOTPATCH_HAS_YASM)
		if (HOTPATCH_HAS_NASM)
			message(STATUS "Using nasm - yes")
			message(STATUS "Using yasm - no")
			set(HOTPATCH_ASM ${HOTPATCH_NASM} CACHE INTERNAL "" FORCE)
		else (HOTPATCH_HAS_NASM)
			message(STATUS "Using nasm - no")
			message(STATUS "Using yasm - yes")
			set(HOTPATCH_ASM ${HOTPATCH_YASM} CACHE INTERNAL "" FORCE)
		endif (HOTPATCH_HAS_NASM)
	else (HOTPATCH_HAS_NASM OR HOTPATCH_HAS_YASM)
		message(FATAL_ERROR "Unable to find nasm or yasm."
		" Please install nasm or yasm or both and make it available in the"
		" PATH")
	endif (HOTPATCH_HAS_NASM OR HOTPATCH_HAS_YASM)
	set(HOTPATCH_USE_ASM 1)
	endif (USE_ASM)
endif (UNIX AND ${CMAKE_SYSTEM_NAME} STREQUAL "Linux")

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)
include_directories(${CMAKE_CURRENT_BINARY_DIR}/include)
add_subdirectory(include)
add_subdirectory(src)
if (BUILD_TESTS)
	add_subdirectory(test)
endif (BUILD_TESTS)
