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

#include <stdio.h>
#include <stdlib.h>

#include "udptable.h"
#include "porting.h"

static struct udptable_t udptable;

/*
 * Initialize the UDP table.
 *
 * Allocates memory to store the requested amount of items.
 *
 * Returns 0 if OK, -1 on error.
 */

int
udptable_init(int size)
{
	/* check if we can allocate it, without overflow */
	if (size < 1 || size > (SIZE_MAX / sizeof(udplog_t))) {
		fprintf(stderr, "Invalid udp table size");
		return -1;
	}
	
	/* allocate the required amount of memory */
	if ((udptable.items = malloc(size * sizeof(udplog_t))) == NULL) {
		perror("Couldn't allocate udp table memory");
		return -1;
	}
	
	udptable.size = size;
	udptable.length = 0;
	
	return 0;
}

/*
 * Insert a new entry in the UDP table.
 *
 * Returns 0 if OK, -1 on error.
 */

int
udptable_insert(struct in_addr src_addr, uintmax_t bytes)
{
	struct udplog_t *udplog;
	
	/* check if there is room for another entry */
	if (udptable.size == udptable.length)
		return -1;
	
	/* point to the next free udplog entry */
	udplog = udptable.items + udptable.length;
	
	/* populate the entry */
	udplog->src_addr = src_addr;
	udplog->packets = 1;
	udplog->bytes = bytes;
	
	/* increase the table length */
	++udptable.length;
	
	return 0;
}

/*
 * Update or insert an entry in the UDP table.
 *
 * Returns 0 if OK, -1 on error.
 */

int
udptable_update(struct in_addr src_addr, uintmax_t bytes)
{
	struct udplog_t *udplog;
	
	/* check if there is an existing entry */
	udplog = udptable_find(src_addr);
	
	/* if there was no entry, create one and return */
	if (!udplog)
		return udptable_insert(src_addr, bytes);
	
	/* XXX .. there was an entry */
	
	/* check if we can do this crap without overflow */
	if (
		(UINTMAX_MAX - bytes) < udplog->bytes
		|| UINTMAX_MAX == udplog->packets
	) {
		return -1;
	}
	
	/* XXX .. we can do this crap */
	udplog->bytes += bytes;
	++(udplog->packets);
	
	return 0;
}

/*
 * Find entry in UDP table.
 *
 * Returns pointer to item or NULL if not found.
 */

struct udplog_t *
udptable_find(struct in_addr src_addr)
{
	int i;
	struct udplog_t *udplog;
	
	/* point to first item */
	udplog = udptable.items;
	
	/* find item and return if found */
	for (i = 0; i < udptable.length; ++i, ++udplog)
		if (udplog->src_addr.s_addr == src_addr.s_addr)
			return udplog;
	
	/* item not found */
	return NULL;
}

/*
 * List the entries in the table.
 */

void
udptable_list(void)
{
	int i;
	struct udplog_t *udplog;
	
	/* point to first item */
	udplog = udptable.items;
	
	/* process each item */
	for (i = 0; i < udptable.length; ++i, ++udplog) {
		printf("src: %s packets: %ju bytes: %ju\n",
			inet_ntoa(udplog->src_addr),
			udplog->packets, udplog->bytes);
	}
	
	return;
}
