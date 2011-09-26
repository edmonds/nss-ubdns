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

#include <limits.h>
#include <nss.h>
#include <sys/types.h>
#include <netdb.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <inttypes.h>

#include <stdio.h>

#include "ubdns.h"

#define ALIGN(a) (((a+sizeof(void*)-1)/sizeof(void*))*sizeof(void*))

enum nss_status _nss_ubdns_gethostbyname4_r(
		const char *name,
		struct gaih_addrtuple **pat,
		char *buffer, size_t buflen,
		int *errnop, int *h_errnop,
		int32_t *ttlp);

enum nss_status _nss_ubdns_gethostbyname3_r(
		const char *name,
		int af,
		struct hostent *host,
		char *buffer, size_t buflen,
		int *errnop, int *h_errnop,
		int32_t *ttlp,
		char **canonp);

enum nss_status _nss_ubdns_gethostbyname2_r(
		const char *name,
		int af,
		struct hostent *host,
		char *buffer, size_t buflen,
		int *errnop, int *h_errnop);

enum nss_status _nss_ubdns_gethostbyname_r(
		const char *name,
		struct hostent *host,
		char *buffer, size_t buflen,
		int *errnop, int *h_errnop);

enum nss_status _nss_ubdns_gethostbyaddr2_r(
		const void* addr, socklen_t len,
		int af,
		struct hostent *host,
		char *buffer, size_t buflen,
		int *errnop, int *h_errnop,
		int32_t *ttlp);

enum nss_status _nss_ubdns_gethostbyaddr_r(
		const void* addr, socklen_t len,
		int af,
		struct hostent *host,
		char *buffer, size_t buflen,
		int *errnop, int *h_errnop);

enum nss_status _nss_ubdns_gethostbyname4_r(
		const char *hn,
		struct gaih_addrtuple **pat,
		char *buffer, size_t buflen,
		int *errnop, int *h_errnop,
		int32_t *ttlp)
{
	size_t l, idx, ms;
	char *r_name;
	struct gaih_addrtuple *r_tuple, *r_tuple_prev = NULL;
	struct address *addresses = NULL, *a;
	unsigned n_addresses = 0, n;

	/* If this fails, n_addresses is 0. Which is fine */
	ubdns_lookup_forward(hn, AF_UNSPEC, &addresses, &n_addresses);
	if (n_addresses == 0) {
		*errnop = ENOENT;
		*h_errnop = HOST_NOT_FOUND;
		return (NSS_STATUS_NOTFOUND);
	}

	l = strlen(hn);
	ms = ALIGN(l+1)+ALIGN(sizeof(struct gaih_addrtuple))*(n_addresses > 0 ? n_addresses : 2);
	if (buflen < ms) {
		*errnop = ENOMEM;
		*h_errnop = NO_RECOVERY;
		free(addresses);
		return NSS_STATUS_TRYAGAIN;
	}

	/* First, fill in hostname */
	r_name = buffer;
	memcpy(r_name, hn, l+1);
	idx = ALIGN(l+1);

	/* Second, fill actual addresses in, but in backwards order */
	for (a = addresses + n_addresses - 1, n = 0; n < n_addresses; n++, a--) {
		r_tuple = (struct gaih_addrtuple*) (buffer + idx);
		r_tuple->next = r_tuple_prev;
		r_tuple->name = r_name;
		r_tuple->family = a->family;
		r_tuple->scopeid = 0;
		memcpy(r_tuple->addr, a->address, 16);

		idx += ALIGN(sizeof(struct gaih_addrtuple));
		r_tuple_prev = r_tuple;
	}

	/* Verify the size matches */
	assert(idx == ms);

	*pat = r_tuple_prev;

	if (ttlp)
		*ttlp = 0;

	free(addresses);

	return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_ubdns_gethostbyname3_r(
		const char *hn,
		int af,
		struct hostent *result,
		char *buffer, size_t buflen,
		int *errnop, int *h_errnop,
		int32_t *ttlp,
		char **canonp)
{
	size_t l, idx, ms;
	char *r_addr, *r_name, *r_aliases, *r_addr_list;
	size_t alen;
	struct address *addresses = NULL, *a;
	unsigned n_addresses = 0, n, c;
	unsigned i = 0;

	if (af != AF_INET && af != AF_INET6) {
		*errnop = EAFNOSUPPORT;
		*h_errnop = NO_DATA;
		return (NSS_STATUS_UNAVAIL);
	}

	alen = PROTO_ADDRESS_SIZE(af);

	ubdns_lookup_forward(hn, af, &addresses, &n_addresses);
	for (a = addresses, n = 0, c = 0; n < n_addresses; a++, n++)
		if (af == a->family)
			c++;

	if (c == 0) {
		*errnop = ENOENT;
		*h_errnop = HOST_NOT_FOUND;
		return (NSS_STATUS_NOTFOUND);
	}

	l = strlen(hn);
	ms = ALIGN(l + 1) +
		sizeof(char *) +
		c * ALIGN(alen) +
		(c + 1) * sizeof(char *);

	if (buflen < ms) {
		*errnop = ENOMEM;
		*h_errnop = NO_RECOVERY;
		free(addresses);
		return NSS_STATUS_TRYAGAIN;
	}

	/* First, fill in hostname */
	r_name = buffer;
	memcpy(r_name, hn, l+1);
	idx = ALIGN(l+1);

	/* Second, create (empty) aliases array */
	r_aliases = buffer + idx;
	*(char**) r_aliases = NULL;
	idx += sizeof(char*);

	/* Third, add addresses */
	r_addr = buffer + idx;
	i = 0;
	for (a = addresses, n = 0; n < n_addresses; a++, n++) {
		if (af != a->family)
			continue;

		memcpy(r_addr + i*ALIGN(alen), a->address, alen);
		i++;
	}

	assert(i == c);
	idx += c*ALIGN(alen);

	/* Fourth, add address pointer array */
	r_addr_list = buffer + idx;
	i = 0;
	for (a = addresses, n = 0; n < n_addresses; a++, n++) {
		if (af != a->family)
			continue;

		((char**) r_addr_list)[i] = (r_addr + i*ALIGN(alen));
		i++;
	}

	assert(i == c);
	((char**) r_addr_list)[c] = NULL;
	idx += (c+1)*sizeof(char*);

	/* Verify the size matches */
	assert(idx == ms);

	result->h_name = r_name;
	result->h_aliases = (char**) r_aliases;
	result->h_addrtype = af;
	result->h_length = alen;
	result->h_addr_list = (char**) r_addr_list;

	if (ttlp)
		*ttlp = 0;

	if (canonp)
		*canonp = r_name;

	free(addresses);

	return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_ubdns_gethostbyname2_r(
		const char *name,
		int af,
		struct hostent *host,
		char *buffer, size_t buflen,
		int *errnop, int *h_errnop)
{
	return _nss_ubdns_gethostbyname3_r(
			name,
			af,
			host,
			buffer, buflen,
			errnop, h_errnop,
			NULL,
			NULL);
}

enum nss_status _nss_ubdns_gethostbyname_r(
		const char *name,
		struct hostent *host,
		char *buffer, size_t buflen,
		int *errnop, int *h_errnop)
{
	return _nss_ubdns_gethostbyname3_r(
			name,
			AF_INET,
			host,
			buffer, buflen,
			errnop, h_errnop,
			NULL,
			NULL);
}

enum nss_status _nss_ubdns_gethostbyaddr2_r(
		const void* addr, socklen_t len,
		int af,
		struct hostent *result,
		char *buffer, size_t buflen,
		int *errnop, int *h_errnop,
		int32_t *ttlp)
{
	char *hn = NULL;
	char *r_name, *r_addr, *r_aliases, *r_addr_list;
	size_t l, idx, ms, alen;

	alen = PROTO_ADDRESS_SIZE(af);

	if (len != alen) {
		*errnop = EINVAL;
		*h_errnop = NO_RECOVERY;
		return NSS_STATUS_UNAVAIL;
	}

	if (af != AF_INET && af != AF_INET6) {
		*errnop = EAFNOSUPPORT;
		*h_errnop = NO_DATA;
		return NSS_STATUS_UNAVAIL;
	}

	hn = ubdns_lookup_reverse(addr, af);
	if (!hn) {
		*errnop = ENOENT;
		*h_errnop = HOST_NOT_FOUND;

		return NSS_STATUS_NOTFOUND;
	}

	l = strlen(hn);
	ms = ALIGN(l + 1) +
		sizeof(char *) +
		ALIGN(alen) +
		2 * sizeof(char *);

	if (buflen < ms) {
		*errnop = ENOMEM;
		*h_errnop = NO_RECOVERY;
		free(hn);
		return (NSS_STATUS_TRYAGAIN);
	}

	/* First, fill in hostname */
	r_name = buffer;
	memcpy(r_name, hn, l + 1);
	idx = ALIGN(l + 1);

	/* Second, create (empty) aliases array */
	r_aliases = buffer + idx;
	*(char **) r_aliases = NULL;
	idx += sizeof(char *);

	/* Third, add address */
	r_addr = buffer + idx;
	memcpy(r_addr, addr, alen);
	idx += ALIGN(alen);

	/* Fourth, add address pointer array */
	r_addr_list = buffer + idx;
	((char **) r_addr_list)[0] = r_addr;

	((char **) r_addr_list)[1] = NULL;
	idx += 2*sizeof(char *);

	assert(idx == ms);

	result->h_name = r_name;
	result->h_aliases = (char **) r_aliases;
	result->h_addrtype = af;
	result->h_length = alen;
	result->h_addr_list = (char **) r_addr_list;

	if (ttlp)
		*ttlp = 0;

	free(hn);

	return (NSS_STATUS_SUCCESS);
}

enum nss_status _nss_ubdns_gethostbyaddr_r(
		const void* addr, socklen_t len,
		int af,
		struct hostent *host,
		char *buffer, size_t buflen,
		int *errnop, int *h_errnop)
{
	return _nss_ubdns_gethostbyaddr2_r(
			addr, len,
			af,
			host,
			buffer, buflen,
			errnop, h_errnop,
			NULL);
}
