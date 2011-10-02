/*
 * Copyright (C) 2011 Robert S. Edmonds
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/***
  This file is part of nss-myhostname.

  Copyright 2008-2011 Lennart Poettering

  nss-myhostname is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public License
  as published by the Free Software Foundation; either version 2.1 of
  the License, or (at your option) any later version.

  nss-myhostname is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with nss-myhostname; If not, see
  <http://www.gnu.org/licenses/>.
***/

#ifndef UBDNS_H
#define UBDNS_H

#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <assert.h>
#include <inttypes.h>
#include <time.h>

#define UBDNS_LUCONF		"/etc/ubdns/libunbound.conf"
#define UBDNS_KEYDIR		"/etc/ubdns/keys"
#define UBDNS_RESOLVCONF	"/etc/ubdns/resolv.conf"
#define SYSTEM_RESOLVCONF	"/etc/resolv.conf"

#define UBDNS_PRESLEN_NAME	1025
#define UBDNS_TYPE_A		1
#define UBDNS_TYPE_PTR		12
#define UBDNS_TYPE_AAAA		28

struct address {
	unsigned char family;
	uint8_t address[16];
	unsigned char scope;
};

void arpa_qname_ip4(const void *addr, char **res);
void arpa_qname_ip6(const void *addr, char **res);

size_t domain_to_str(const uint8_t *src, size_t src_len, char *dst);

void timespec_get(struct timespec *ts);
void timespec_sub(const struct timespec *a, struct timespec *b);
double timespec_to_double(const struct timespec *ts);

int ubdns_lookup_forward(const char *hn, int af, struct address **_list, unsigned *_n_list);
char *ubdns_lookup_reverse(const void *addr, int af);

static inline size_t PROTO_ADDRESS_SIZE(int proto) {
	assert(proto == AF_INET || proto == AF_INET6);
	return proto == AF_INET6 ? 16 : 4;
}

static inline int address_compare(const void *_a, const void *_b) {
	const struct address *a = _a, *b = _b;

	/* Order lowest scope first, IPv4 before IPv6, lowest interface index first */

	if (a->scope < b->scope)
		return -1;
	if (a->scope > b->scope)
		return 1;

	if (a->family == AF_INET && b->family == AF_INET6)
		return -1;
	if (a->family == AF_INET6 && b->family == AF_INET)
		return 1;

	return 0;
}

#endif /* UBDNS_H */
