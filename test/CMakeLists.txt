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
project(unit_tests)

include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${CMAKE_CURRENT_BINARY_DIR})

if (ARCH STREQUAL "x86_64")
add_executable(ptracetest ptrace.c)
endif (ARCH STREQUAL "x86_64")

add_executable(dummy dummy.c)
add_executable(loadertest loader.c)
target_link_libraries(loadertest hotpatch)
add_test(loadertest ${CMAKE_CURRENT_BINARY_DIR}/loadertest)

add_executable(compiletestcpp cpptest.cpp)
target_link_libraries(compiletestcpp hotpatch)
add_test(compiletestcpp ${CMAKE_CURRENT_BINARY_DIR}/compiletestcpp)

add_executable(compiletestc ctest.c)
target_link_libraries(compiletestc hotpatch)
add_test(compiletestc ${CMAKE_CURRENT_BINARY_DIR}/compiletestc)

add_library(hotpatchtest SHARED dlltest.c)
set_target_properties(hotpatchtest PROPERTIES LINK_FLAGS "-fPIC -nostartfiles")
install(TARGETS hotpatchtest LIBRARY DESTINATION lib)
