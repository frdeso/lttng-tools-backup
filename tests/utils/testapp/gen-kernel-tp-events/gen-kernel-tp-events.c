/*
 * Copyright (C) - 2017 Francis Deslauriers <francis.deslauriers@efficios.com>
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License
 * for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA
 */

#define _LGPL_SOURCE
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

void sig_handler(int signum)
{
}

int main(int argc, char **argv)
{
	int fd, ret = 0;
	struct sigaction sig_action;

	if (argc < 4) {
		ret = -1;
		fprintf(stderr, "%s EVENT_NAME ARG UUID...", argv[0]);
		goto end;
	}

	/**
	 * Register a signal handler and wait for a signal from the parent
	 * process to go on with the syscalls.
	 */
	sig_action.sa_handler = sig_handler;
	sigemptyset(&sig_action.sa_mask);

	ret = sigaction(SIGUSR1, &sig_action, NULL);
	if (ret == -1) {
		perror("sigaction");
		goto end;
	}

	pause();

	fd = open("/proc/lttng-test/gen-kernel-events", O_WRONLY);
	if (fd < 0) {
		perror("open");
		ret = -1;
		goto end;
	}

	ret = dprintf(fd, "%s %s %s", argv[1], argv[2], argv[3]);
	if (ret < 0) {
		goto close_end;
	}

close_end:
	ret = close(fd);
	if (ret == -1) {
		perror("close");
	}
end:
	exit(!ret ? EXIT_SUCCESS : EXIT_FAILURE);
}
