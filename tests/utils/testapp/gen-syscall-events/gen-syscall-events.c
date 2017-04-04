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

#define MAX_LEN 16

void sig_handler(int signum)
{
}

int main(int argc, char **argv)
{
	int fd, ret = 0;
	char buf[MAX_LEN];
	struct sigaction sig_action;

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

	fd = open("/etc/passwd", O_RDONLY);
	if (fd < 0) {
		perror("open");
		ret = -1;
		goto end;
	}

	ret = read(fd, buf, MAX_LEN);
	if (ret < 0) {
		perror("read");
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
