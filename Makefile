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
CMAKE=$(shell which cmake)
CTEST=$(shell which ctest)
PREFIX?=/usr/local
ARCH=$(shell uname -m)

default: release
.PHONY: default

all: release debug
.PHONY: all

clean: cleanrelease
.PHONY: clean

test: testrelease
.PHONY: test

install: installrelease
.PHONY: install

release:
	@mkdir -p Release
	@cd Release && $(CMAKE) -DARCH=$(ARCH) -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=$(PREFIX) ..
	@cd Release && $(MAKE)
	@echo "Release Build complete"
.PHONY: release

debug:
	@mkdir -p Debug
	@cd Debug && $(CMAKE) -DARCH=$(ARCH) -DCMAKE_BUILD_TYPE=Debug -DCMAKE_INSTALL_PREFIX=$(PREFIX) ..
	@cd Debug && $(MAKE)
	@echo "Debug Build complete"
.PHONY: debug

cleanrelease:
	@if test -d Release; then cd Release && $(MAKE) clean; fi
	@if test -d Release; then cd Release && rm -f CMakeCache.txt; fi
	@if test -d Release; then echo "Release Cleaning complete"; else echo "Nothing to clean"; fi
.PHONY: cleanrelease

cleandebug:
	@if test -d Debug; then cd Debug && $(MAKE) clean; fi
	@if test -d Debug; then cd Debug && rm -f CMakeCache.txt; fi
	@if test -d Debug; then echo "Debug Cleaning complete"; else echo "Nothing to clean"; fi
.PHONY: cleandebug

testrelease: release
	cd Release && $(CTEST)
.PHONY: testrelease

testdebug: debug
	cd Debug && $(CTEST)
.PHONY: testdebug

installrelease: release
	@cd Release && $(CMAKE) -DARCH=$(ARCH) -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=$(PREFIX) ..
	@cd Release && $(MAKE) install
	@echo "Release installation complete"
.PHONY: installrelease

installdebug: debug
	@cd Debug && $(CMAKE) -DARCH=$(ARCH) -DCMAKE_BUILD_TYPE=Debug -DCMAKE_INSTALL_PREFIX=$(PREFIX) ..
	@cd Debug && $(MAKE) install
	@echo "Debug installation complete"
.PHONY: installdebug

