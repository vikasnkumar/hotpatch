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
project(unit_tests)

include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${CMAKE_CURRENT_BINARY_DIR})

add_executable(ptracetest ptrace.c)
target_link_libraries(ptracetest ${HOTPATCH_DEP_LIBS})
add_test(ptracetest ${CMAKE_CURRENT_BINARY_DIR}/ptracetest)

add_executable(dummy dummy.c)
add_executable(selftest self.c)
target_link_libraries(selftest ${HOTPATCH_DEP_LIBS})
add_test(selftest ${CMAKE_CURRENT_BINARY_DIR}/selftest)

add_executable(cpptest cpptest.cpp)
target_link_libraries(cpptest hotpatch)
add_test(cpptest ${CMAKE_CURRENT_BINARY_DIR}/cpptest)
