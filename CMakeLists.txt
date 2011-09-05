### hotpatch is a dll injection strategy
### Copyright (C) 2010-2011  Vikas Naresh Kumar
###
### This program is free software: you can redistribute it and/or modify
### it under the terms of the GNU General Public License as published by
### the Free Software Foundation, either version 3 of the License, or
### (at your option) any later version.
###
### This program is distributed in the hope that it will be useful,
### but WITHOUT ANY WARRANTY; without even the implied warranty of
### MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
### GNU General Public License for more details.
###
### You should have received a copy of the GNU General Public License
### along with this program.  If not, see <http://www.gnu.org/licenses/>.
cmake_minimum_required(VERSION 2.6 FATAL_ERROR)

option(DEBUG "In Debug mode" ON)
if (NOT CMAKE_BUILD_TYPE STREQUAL "Debug")
	set(DEBUG OFF)
endif (NOT CMAKE_BUILD_TYPE STREQUAL "Debug")

if (CMAKE_COMPILER_IS_GNUCC)
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -fPIC -pedantic -ansi -posix")
	set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -O0 -fno-inline")
	set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -O2")
endif (CMAKE_COMPILER_IS_GNUCC)
include(CTest)
include(CheckFunctionExists)
include(CheckIncludeFile)
include(CheckIncludeFiles)
include(CheckSymbolExists)
include(CheckTypeSize)
if (WIN32)
	message(FATAL_ERROR "Windows is not supported")
endif (WIN32)
check_include_file("features.h" HOTPATCH_HAS_FEATURES_H)
check_include_file("errno.h" HOTPATCH_HAS_ERRNO_H)
check_include_file("stdio.h" HOTPATCH_HAS_STDIO_H)
check_include_file("stdlib.h" HOTPATCH_HAS_STDLIB_H)
check_include_file("string.h" HOTPATCH_HAS_STRING_H)
check_function_exists("strnlen" HOTPATCH_HAS_STRNLEN_FN)
check_include_file("stddef.h" HOTPATCH_HAS_STDDEF_H)
check_include_file("stdint.h" HOTPATCH_HAS_STDINT_H)
check_include_file("stdarg.h" HOTPATCH_HAS_STDARG_H)
check_include_file("stdbool.h" HOTPATCH_HAS_STDBOOL_H)
check_include_file("time.h" HOTPATCH_HAS_TIME_H)
check_include_file("sys/types.h" HOTPATCH_HAS_SYS_TYPES_H)
check_include_file("unistd.h" HOTPATCH_HAS_UNISTD_H)
check_include_file("assert.h" HOTPATCH_HAS_ASSERT_H)
# look for mach kernel header files
if (APPLE AND ${CMAKE_SYSTEM_NAME} STREQUAL "Darwin")
	check_include_file("mach/message.h" HOTPATCH_HAS_MACH_MESSAGE_H)
	check_include_file("mach/mach.h" HOTPATCH_HAS_MACH_MACH_H)
	check_include_file("mach/task.h" HOTPATCH_HAS_MACH_TASK_H)
	check_include_file("mach/mach_traps.h" HOTPATCH_HAS_MACH_MACHTRAPS_H)
	check_include_file("mach/mach_error.h" HOTPATCH_HAS_MACH_MACHERROR_H)
	check_function_exists("task_for_pid" HOTPATCH_HAS_MACH_TASKFORPID_FN)
endif (APPLE AND ${CMAKE_SYSTEM_NAME} STREQUAL "Darwin")
if (UNIX AND ${CMAKE_SYSTEM_NAME} STREQUAL "Linux")
	check_include_file("elf.h" HOTPATCH_HAS_LINUX_ELF_H)
	check_include_file("dlfcn.h" HOTPATCH_HAS_LINUX_DLFCN_H)
	if (HOTPATCH_HAS_LINUX_DLFCN_H)
		set(HOTPATCH_DEP_LIBS ${HOTPATCH_DEP_LIBS} dl)
	endif (HOTPATCH_HAS_LINUX_DLFCN_H)
	check_include_file("link.h" HOTPATCH_HAS_LINUX_LINK_H)
	check_include_file("pthread.h" HOTPATCH_HAS_LINUX_PTHREAD_H)
	if (HOTPATCH_HAS_LINUX_PTHREAD_H)
		set(HOTPATCH_DEP_LIBS ${HOTPATCH_DEP_LIBS} pthread)
	endif (HOTPATCH_HAS_LINUX_PTHREAD_H)
	check_include_file("setjmp.h" HOTPATCH_HAS_LINUX_SETJMP_H)
	check_include_file("signal.h" HOTPATCH_HAS_LINUX_SIGNAL_H)
	check_include_file("sys/ptrace.h" HOTPATCH_HAS_LINUX_SYS_PTRACE_H)
	check_include_file("sys/wait.h" HOTPATCH_HAS_LINUX_SYS_WAIT_H)
	check_include_file("sys/stat.h" HOTPATCH_HAS_LINUX_SYS_STAT_H)
	check_include_file("fcntl.h" HOTPATCH_HAS_LINUX_FCNTL_H)
	check_include_files("sys/types.h;sys/user.h" HOTPATCH_HAS_LINUX_SYS_USER_H)
	check_function_exists("dl_iterate_phdr" HOTPATCH_HAS_LINUX_DLITERPHDR_FN)
	check_type_size("void *" HOTPATCH_VOIDPTR_SIZE) 
	if (NOT HAVE_HOTPATCH_VOIDPTR_SIZE)
		message(FATAL_ERROR "(void *) does not seem to be supported.")
	endif(NOT HAVE_HOTPATCH_VOIDPTR_SIZE)
endif (UNIX AND ${CMAKE_SYSTEM_NAME} STREQUAL "Linux")

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)
include_directories(${CMAKE_CURRENT_BINARY_DIR}/include)
add_subdirectory(include)
add_subdirectory(src)
add_subdirectory(test)
