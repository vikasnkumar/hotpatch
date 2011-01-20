### dyldo is a dll injection strategy
### Copyright (C) 2010  Vikas Naresh Kumar
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
	if (DEBUG)
		set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -O0")
		#set(CMAKE_VERBOSE_MAKEFILE TRUE)
	endif (DEBUG)
endif (CMAKE_COMPILER_IS_GNUCC)
include(CTest)
include(CheckFunctionExists)
include(CheckIncludeFile)
include(CheckIncludeFiles)
include(CheckSymbolExists)
include(CheckTypeSize)
# look for mach kernel header files
check_include_file("errno.h" DYLDO_HAS_ERRNO_H)
check_include_file("stdio.h" DYLDO_HAS_STDIO_H)
check_include_file("stdlib.h" DYLDO_HAS_STDLIB_H)
check_include_file("string.h" DYLDO_HAS_STRING_H)
check_include_file("stdint.h" DYLDO_HAS_STDINT_H)
check_include_file("stddef.h" DYLDO_HAS_STDDEF_H)
check_include_file("stdarg.h" DYLDO_HAS_STDARG_H)
check_include_file("time.h" DYLDO_HAS_TIME_H)
check_include_file("sys/types.h" DYLDO_HAS_SYS_TYPES_H)
check_include_file("unistd.h" DYLDO_HAS_UNISTD_H)
check_include_file("assert.h" DYLDO_HAS_ASSERT_H)
if (APPLE AND ${CMAKE_SYSTEM_NAME} STREQUAL "Darwin")
	check_include_file("mach/message.h" DYLDO_HAS_MACH_MESSAGE_H)
	check_include_file("mach/mach.h" DYLDO_HAS_MACH_MACH_H)
	check_include_file("mach/task.h" DYLDO_HAS_MACH_TASK_H)
	check_include_file("mach/mach_traps.h" DYLDO_HAS_MACH_MACHTRAPS_H)
	check_include_file("mach/mach_error.h" DYLDO_HAS_MACH_MACHERROR_H)
	check_function_exists("task_for_pid" DYLDO_HAS_MACH_TASKFORPID_FN)
endif (APPLE AND ${CMAKE_SYSTEM_NAME} STREQUAL "Darwin")
if (UNIX AND ${CMAKE_SYSTEM_NAME} STREQUAL "Linux")
	check_include_file("elf.h" DYLDO_HAS_LINUX_ELF_H)
	check_include_file("dlfcn.h" DYLDO_HAS_LINUX_DLFCN_H)
	if (DYLDO_HAS_LINUX_DLFCN_H)
		set(DYLDO_USES_LIBRARIES ${DYLDO_USES_LIBRARIES} dl)
	endif (DYLDO_HAS_LINUX_DLFCN_H)
	check_include_file("link.h" DYLDO_HAS_LINUX_LINK_H)
	check_include_file("pthread.h" DYLDO_HAS_LINUX_PTHREAD_H)
	if (DYLDO_HAS_LINUX_PTHREAD_H)
		set(DYLDO_USES_LIBRARIES ${DYLDO_USES_LIBRARIES} pthread)
	endif (DYLDO_HAS_LINUX_PTHREAD_H)
	check_include_file("setjmp.h" DYLDO_HAS_LINUX_SETJMP_H)
	check_include_file("signal.h" DYLDO_HAS_LINUX_SIGNAL_H)
	check_include_file("sys/ptrace.h" DYLDO_HAS_LINUX_SYS_PTRACE_H)
	check_include_file("sys/wait.h" DYLDO_HAS_LINUX_SYS_WAIT_H)
	check_include_file("sys/stat.h" DYLDO_HAS_LINUX_SYS_STAT_H)
	check_include_file("fcntl.h" DYLDO_HAS_LINUX_FCNTL_H)
	check_include_files("sys/types.h;sys/user.h" DYLDO_HAS_LINUX_SYS_USER_H)
	check_function_exists("dl_iterate_phdr" DYLDO_HAS_LINUX_DLITERPHDR_FN)
	check_type_size("void *" DYLDO_VOIDPTR_SIZE) 
	if (NOT HAVE_DYLDO_VOIDPTR_SIZE)
		message(FATAL_ERROR "(void *) does not seem to be supported.")
	endif(NOT HAVE_DYLDO_VOIDPTR_SIZE)
endif (UNIX AND ${CMAKE_SYSTEM_NAME} STREQUAL "Linux")

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)
include_directories(${CMAKE_CURRENT_BINARY_DIR}/include)
add_subdirectory(include)
add_subdirectory(src)
add_subdirectory(test)
