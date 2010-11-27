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

if (CMAKE_C_COMPILER STREQUAL "GNU")
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -fPIC -pedantic -ansi -posix")
	if (DEBUG)
		set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -O0")
	endif (DEBUG)
endif (CMAKE_C_COMPILER STREQUAL "GNU")
include(CTest)
include(CheckFunctionExists)
include(CheckIncludeFile)
include(CheckIncludeFiles)
include(CheckSymbolExists)
include(CheckTypeSize)

# look for mach kernel header files
check_include_file("stdio.h" DYLDO_HAS_STDIO_H)
check_include_file("stdlib.h" DYLDO_HAS_STDLIB_H)
check_include_file("string.h" DYLDO_HAS_STRING_H)
check_include_file("stdint.h" DYLDO_HAS_STDINT_H)
check_include_file("time.h" DYLDO_HAS_TIME_H)
check_include_file("sys/types.h" DYLDO_HAS_SYS_TYPES_H)
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
	check_include_file("link.h" DYLDO_HAS_LINUX_LINK_H)
	check_include_file("pthread.h" DYLDO_HAS_LINUX_PTHREAD_H)
	check_include_file("setjmp.h" DYLDO_HAS_LINUX_SETJMP_H)
	check_include_file("signal.h" DYLDO_HAS_LINUX_SIGNAL_H)
	check_include_file("sys/ptrace.h" DYLDO_HAS_LINUX_SYS_PTRACE_H)
	check_function_exists("dl_iterate_phdr" DYLDO_HAS_LINUX_DLITERPHDR_FN)
endif (UNIX AND ${CMAKE_SYSTEM_NAME} STREQUAL "Linux")

include_directories(include)
add_subdirectory(include)
add_subdirectory(src)
add_subdirectory(test)
