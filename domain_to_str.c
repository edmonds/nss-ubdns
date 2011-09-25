/* domain_to_str.c - convert wire-format DNS name to presentation format
 * from wreck/wdns/msg/domain_to_str.c
 */

/*
 * Copyright (c) 2009, 2010 by Internet Systems Consortium, Inc. ("ISC")
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
#include <stdint.h>
#include <stdio.h>

/**
 * Convert a domain name to a human-readable string.
 *
 * \param[in] src domain name in wire format
 * \param[in] src_len length of domain name in bytes
 * \param[out] dst caller-allocated string buffer of size WDNS_PRESLEN_NAME
 * 
 * \return Number of bytes read from src.
 */

size_t
domain_to_str(const uint8_t *src, size_t src_len, char *dst) {
	size_t bytes_read = 0;
	size_t bytes_remaining = src_len;
	uint8_t oclen;

	assert(src != NULL);

	oclen = *src;
	while (bytes_remaining > 0 && oclen != 0) {
		src++;
		bytes_remaining--;

		bytes_read += oclen + 1 /* length octet */;

		while (oclen-- && bytes_remaining > 0) {
			uint8_t c = *src++;
			bytes_remaining--;

			if (c == '.') {
				*dst++ = '\\';
				*dst++ = c;
			} else if (c >= '!' && c <= '~') {
				*dst++ = c;
			} else {
				snprintf(dst, 5, "\\%.3d", c);
				dst += 4;
			}
		}
		*dst++ = '.';
		oclen = *src;
	}
	if (bytes_read == 0)
		*dst++ = '.';
	bytes_read++;

	*dst = '\0';
	return (bytes_read);
}
