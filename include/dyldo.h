/*
 *  dyldo is a dll injection strategy.
 *  Copyright (C) 2010-2011 Vikas Naresh Kumar
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef __DYLDO_H__
#define __DYLDO_H__

#include <dyldo_config.h>

void *dyldo_takeout();

int dyldo_insert(void *dyldo, pid_t pid, const char *dll, const char *symbol, void *arg);

void dyldo_putback(void *dyldo);

#endif /* __DYLDO_H__ */
