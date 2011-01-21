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
project(dyldo)

add_definitions(-D_BSD_SOURCE)
add_library(dyldo SHARED dyldo.c)
target_link_libraries(dyldo dl elf)
