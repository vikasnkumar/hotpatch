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
project(hotpatch)

include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${CMAKE_CURRENT_BINARY_DIR})

if (USE_ASM)
foreach (ASM_VAR call32 call64)
	set(ASM_F ${CMAKE_CURRENT_SOURCE_DIR}/${ASM_VAR}.s)
	set(ASM_F_OBJ ${CMAKE_CURRENT_BINARY_DIR}/${ASM_VAR}.o)
	set(ASM_F_HDR ${CMAKE_CURRENT_BINARY_DIR}/${ASM_VAR}.h)
	set(ASM_F_VAR hotpatch_${ASM_VAR})
	set(ASM2HDR ${CMAKE_CURRENT_SOURCE_DIR}/asm2hdr.pl)
	if (HOTPATCH_ASM AND PERL_FOUND)
		add_custom_command(OUTPUT ${ASM_F_HDR}
			COMMAND ${HOTPATCH_ASM} ARGS ${ASM_F} -o ${ASM_F_OBJ}
			COMMAND ${PERL_EXECUTABLE} ARGS ${ASM2HDR} ${ASM_F_OBJ}
			${ASM_F_HDR} ${ASM_F_VAR}
			DEPENDS ${ASM_F} ${ASM2HDR}
			WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
		set(ASM_HEADERS ${ASM_HEADERS} ${ASM_F_HDR})
	else (HOTPATCH_ASM AND PERL_FOUND)
		message(FATAL_ERROR "You need Perl for this")
	endif (HOTPATCH_ASM AND PERL_FOUND)
endforeach (ASM_VAR call32 call64)
add_custom_target(asm_header DEPENDS ${ASM_HEADERS})
endif (USE_ASM)

add_library(hotpatch SHARED hotpatch.c exedetails.c loader.c)
add_library(hotpatch_s STATIC hotpatch.c exedetails.c loader.c)
if (USE_ASM)
	add_dependencies(hotpatch asm_header)
	add_dependencies(hotpatch_s asm_header)
endif (USE_ASM)
set_target_properties(hotpatch_s PROPERTIES OUTPUT_NAME "hotpatch"
	CLEAN_DIRECT_OUTPUT 1)
set_target_properties(hotpatch PROPERTIES CLEAN_DIRECT_OUTPUT 1)
install(TARGETS hotpatch LIBRARY DESTINATION lib)
install(TARGETS hotpatch_s ARCHIVE DESTINATION lib)

if (BUILD_HOTPATCHER)
	add_executable(hotpatcher main.c)
	target_link_libraries(hotpatcher hotpatch_s)
	install(TARGETS hotpatcher RUNTIME DESTINATION bin)
endif (BUILD_HOTPATCHER)
