### dyldo is a dll injection strategy
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

add_executable(test1 ptrace.c)
target_link_libraries(test1 ${DYLDO_USES_LIBRARIES})
add_test(test1 ${CMAKE_CURRENT_BINARY_DIR}/test1)

add_executable(dummy dummy.c)
add_executable(test2 self.c)
target_link_libraries(test2 ${DYLDO_USES_LIBRARIES})
add_test(test2 ${CMAKE_CURRENT_BINARY_DIR}/test2)
