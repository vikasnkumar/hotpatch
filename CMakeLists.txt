### dyldo is a dll injection strategy for the Mac.
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
cmake_minimum_required(VERSION 2.8 FATAL_ERROR)
enable_testing()
option(DEBUG "In Debug mode" ON)
if (NOT CMAKE_BUILD_TYPE STREQUAL "Debug")
	set(DEBUG OFF)
endif (NOT CMAKE_BUILD_TYPE STREQUAL "Debug")

if (CMAKE_C_COMPILER STREQUAL "GNU")
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -fPIC -pedantic -ansi")
	if (DEBUG)
		set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -O0")
	endif (DEBUG)
endif (CMAKE_C_COMPILER STREQUAL "GNU")

include(CheckFunctionExists)
include(CheckIncludeFile)
include(CheckIncludeFiles)
include(CheckSymbolExists)
include(CheckTypeSize)

# look for mach kernel header files
check_include_file("mach/message.h" HAVE_MACH_MESSAGE_H)
check_include_file("mach/mach.h" HAVE_MACH_MACH_H)
check_include_file("mach/task.h" HAVE_MACH_TASK_H)
check_include_file("mach/mach_traps.h" HAVE_MACH_MACHTRAPS_H)
check_include_file("mach/mach_error.h" HAVE_MACH_MACHERROR_H)
check_include_file("stdio.h" HAVE_LIBC_STDIO_H)
check_function_exists("task_for_pid" HAVE_TASKFORPID_FN)
