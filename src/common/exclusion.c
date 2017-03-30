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
#include <assert.h>

#include "exclusion.h"

int compare_exclusion(const struct lttng_event_exclusion *left_exclusion,
				const struct lttng_event_exclusion *right_exclusion)
{
	/* If only one of the exclusions is NULL, fail. */
	if ((left_exclusion && !right_exclusion) || (!left_exclusion && right_exclusion)) {
		goto different;
	}

	if (left_exclusion && right_exclusion) {
		size_t i;

		/* Check exclusion counts first. */
		if (left_exclusion->count != right_exclusion->count) {
			goto different;
		}

		/* Compare names individually. */
		for (i = 0; i < left_exclusion->count; ++i) {
			size_t j;
		        int found = 0;
			const char *name_left =
				LTTNG_EVENT_EXCLUSION_NAME_AT(left_exclusion, i);

			/*
			 * Compare this exclusion name to all the exclusion names.
			 */
			for (j = 0; j < right_exclusion->count; ++j) {
				const char *name_right =
					LTTNG_EVENT_EXCLUSION_NAME_AT(
						right_exclusion, j);

				if (!strncmp(name_left, name_right, LTTNG_SYMBOL_NAME_LEN)) {
					/* Names match! */
					found = 1;
					break;
				}
			}

			/*
			 * If the current exclusion name was not found amongst
			 * the exclusion names, then the exclusions are
			 * different.
			 */
			if (!found) {
				goto different;
			}
		}
	}
	return 0;
different:
	return 1;
}

int validate_exclusion(const struct lttng_event_exclusion *exclusion)
{
	size_t i;
	int ret = 0;

	assert(exclusion);

	for (i = 0; i < exclusion->count; ++i) {
		size_t j;
		const char *name_a =
			LTTNG_EVENT_EXCLUSION_NAME_AT(exclusion, i);

		for (j = 0; j < i; ++j) {
			const char *name_b =
				LTTNG_EVENT_EXCLUSION_NAME_AT(exclusion, j);

			if (!strncmp(name_a, name_b, LTTNG_SYMBOL_NAME_LEN)) {
				/* Found a repeating exclusion */
				ret = -1;
				goto end;
			}
		}
	}

end:
	return ret;
}
