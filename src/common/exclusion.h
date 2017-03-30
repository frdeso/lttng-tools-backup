/*
 * Copyright 2017 - Francis Deslauriers <francis.deslauriers@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License, version 2 only, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef LTTNG_COMMON_EXCLUSION_H
#define LTTNG_COMMON_EXCLUSION_H

#include <common/sessiond-comm/sessiond-comm.h>

/*
 * Compare two exclusions
 *
 * Returns 0 if they are identical, non zero if they differ
 */
int compare_exclusion(const struct lttng_event_exclusion *left_exclusion,
			     const struct lttng_event_exclusion *right_exclusion);

/*
 * Validates an exclusion list.
 *
 * Returns 0 if valid, negative value if invalid.
 */
int validate_exclusion(const struct lttng_event_exclusion *exclusion);

#endif /* LTTNG_COMMON_EXCLUSION_H */
