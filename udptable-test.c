/*
 * Copyright (C) 2012 Jimmy Scott #jimmy#inet-solutions#be#. Belgium.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  1. Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *
 *  3. The names of the authors may not be used to endorse or promote products
 *     derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS "AS IS" AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

#include "udptable.h"
#include "porting.h"

static void usage(char *program);
static int install_sigalrm(void);
static void handle_sigalrm(int signo);

static int global_stop = 0;

int
main(int argc, char **argv)
{
	int size, length;
	struct in_addr src_addr;
	
	/* check usage */
	if (argc != 3 && argc != 4) {
		usage(argv[0]);
		return EXIT_FAILURE;
	}
	
	/* install signal handler to break pcap_loop */
	if (install_sigalrm() != 0)
		return EXIT_FAILURE;
	
	/* Get numbers from input.
	 * Sorry, no input validation. */
	size = atoi(argv[1]);
	length = atoi(argv[2]);
	
	/* create the table of the requested size */
	printf("Creating table of size %i\n", size);
	if (udptable_init(size) != 0) {
		perror("ERROR: Couldn't create table");
		return EXIT_FAILURE;
	}
	
	printf("Populating table with %i entries\n", length);
	while (length > 0)
	{
		/* insert packet from new ip
		 * with size of ethernet frame */
		src_addr.s_addr = length;
		udptable_update(src_addr, 64);
		
		--length;
	}
	
	/* stop if we got 4 params = populate only mode */
	if (argc == 4)
		return EXIT_SUCCESS;
	
	/* stop after 10 seconds */
	alarm(10);
	
	/* set the src addr to something not generated above */
	src_addr.s_addr = 0;
	
	/* keep pushing packets at the end of the table
	 * until the time breaks the loop */
	while (!global_stop)
	{
		udptable_update(src_addr, 64);
	}
	
	/* print table */
	udptable_list();
	
	return EXIT_SUCCESS;
}

static void
usage(char *program)
{
	fprintf(stderr, "usage: %s <tbl-size> <tbl-length> [populate-only]\n", program);
}

static int
install_sigalrm(void)
{
	struct sigaction new_action;
	
	/* setup the new sigalrm handler */
	new_action.sa_handler = handle_sigalrm;
	sigemptyset(&new_action.sa_mask);
	new_action.sa_flags = 0;
	
	/* install the handler */
	if (sigaction(SIGALRM, &new_action, NULL) == -1) {
		perror("ERROR: Couldn't install SIGALRM handler");
		return -1;
	}
	
	return 0;
}

static void
handle_sigalrm(int signo)
{
	int save_errno = errno;
	global_stop = 1;
	errno = save_errno;
}
