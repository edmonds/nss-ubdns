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

#include <assert.h>
#include <ctype.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <unbound.h>

#include "ubdns.h"

static struct ub_ctx *ctx = NULL;

static void __attribute__((constructor))
ubdns_init(void) {
	int ret = 0;

	ctx = ub_ctx_create();
	if (ctx != NULL) {
		int ret;

		ret = ub_ctx_resolvconf(ctx, "/etc/ubdns/resolv.conf");
		if (ret != 0)
			goto out;

		ret = ub_ctx_add_ta_file(ctx, "/var/lib/unbound/root.key");
		if (ret != 0)
			goto out;
	}

out:
	if (ret != 0) {
		if (ctx != NULL)
			ub_ctx_delete(ctx);
		ctx = NULL;
	}
}

static void __attribute__((destructor))
ubdns_finish(void) {
	ub_ctx_delete(ctx);
	ctx = NULL;
}

static bool
ubdns_check_result(struct ub_result *res) {
	if (res->havedata == 0)
		return (false);
	if (res->bogus)
		return (false);

	return (true);
}

static int
ubdns_add_result(struct address **_list, unsigned *_n_list, struct ub_result *res, int af) {
	struct address *list = *_list;
	unsigned n_list = *_n_list;
	int i;

	if (!ubdns_check_result(res))
		return (0);

	for (i = 0; res->data[i] != NULL; i++) {
		if (res->len[i] == PROTO_ADDRESS_SIZE(af)) {
			list = realloc(list, (n_list + 1) * sizeof(struct address));
			if (!list)
				return (-1);

			list[n_list].family = af;
			list[n_list].scope = 0;
			memcpy(list[n_list].address, res->data[i], PROTO_ADDRESS_SIZE(af));
			n_list += 1;
		}
	}

	*_list = list;
	*_n_list = n_list;
	return (0);
}

int
ubdns_lookup_forward(const char *hn, int af, struct address **_list, unsigned *_n_list) {
	struct address *list = NULL;
	unsigned n_list = 0;
	int r = 1;
	int ret;

	struct ub_result *res;

	if (ctx == NULL)
		goto err;

	if (af == AF_INET || af == AF_UNSPEC) {
		ret = ub_resolve(ctx, (char *) hn, 1 /*A*/, 1 /*IN*/, &res);
		if (ret != 0)
			goto err;

		ret = ubdns_add_result(&list, &n_list, res, AF_INET);
		if (ret != 0)
			goto err;

		ub_resolve_free(res);
	}

	if (af == AF_INET6 || af == AF_UNSPEC) {
		ret = ub_resolve(ctx, (char *) hn, 28 /*A*/, 1 /*IN*/, &res);
		if (ret != 0)
			goto err;

		ret = ubdns_add_result(&list, &n_list, res, AF_INET6);
		if (ret != 0)
			goto err;

		ub_resolve_free(res);
	}

finish:
	if (r < 0) {
		free(list);
	} else {
		qsort(list, n_list, sizeof(struct address), address_compare);

		*_list = list;
		*_n_list = n_list;
	}

	return r;
err:
	r = 0;
	goto finish;
}

char *
ubdns_lookup_reverse(const void *addr, int af) {
	struct ub_result *res;
	char *qname = NULL;
	int ret;

	if (ctx == NULL)
		return (NULL);

	if (af == AF_INET) {
		arpa_qname_ip4(addr, &qname);
	} else if (af == AF_INET6) {
		arpa_qname_ip6(addr, &qname);
	} else {
		return (NULL);
	}

	ret = ub_resolve(ctx, qname, 12 /*PTR*/, 1 /*IN*/, &res);

	if (ret == 0 &&
	    ubdns_check_result(res) &&
	    res->data[0] != NULL)
	{
		char name[1025];
		domain_to_str((const uint8_t *) res->data[0], res->len[0], name);
		return (strdup(name));
	}

	return (NULL);
}
