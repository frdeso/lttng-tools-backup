/*
 * Copyright (C) 2011 - Francis Deslauriers <francis.deslauriers@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#define _GNU_SOURCE
#include <assert.h>
#include <stdio.h>
#include <unistd.h>

#include "../command.h"

/*
 *  The 'trace <options>' first level command
 *
 *  Returns one of the CMD_* result constants.
 */
int cmd_trace(int argc, const char **argv)
{
	return CMD_SUCCESS;
}
