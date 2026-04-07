/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2024 Andy Green <andy@warmcat.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 *
 * HTTP Digest Auth (RFC7616) server-side implementation.
 *
 * Supports MD5 and SHA-256 algorithms.  The server sends two WWW-Authenticate
 * headers (one per algorithm) so the client can choose.  Password verification
 * is delegated to the application via LWS_CALLBACK_HTTP_DIGEST_GET_HA1: the
 * application fills H(A1) = H(username:realm:password) from any backend
 * (database, etc.) without ever needing to expose plaintext passwords.
 *
 * Nonce format: rand_hex ":" H( rand_hex ":" timestamp ":" vhost_secret )
 * The random prefix (4 bytes / 8 hex chars) ensures every nonce is unique
 * even when two challenges are issued within the same second.  The hash
 * binds the prefix to the timestamp and a per-vhost secret, so the nonce
 * is unguessable without the secret.  Verification recomputes the hash for
 * timestamps t, t-1, t-2 to tolerate clock drift between challenge and reply.
 *
 */

#include "private-lib-core.h"

#if defined(LWS_WITH_HTTP_DIGEST_AUTH)

/*
 * Token table for parsing Authorization: Digest ... header fields.
 * Index corresponds to the bit position in the `seen` bitmask.
 */
static const char * const digest_toks[] = {
	"Digest",	/* bit  0 — auth type marker     */
	"username",	/* bit  1                        */
	"realm",	/* bit  2                        */
	"nonce",	/* bit  3                        */
	"uri",		/* bit  4 (optional)             */
	"response",	/* bit  5                        */
	"opaque",	/* bit  6 (optional)             */
	"qop",		/* bit  7                        */
	"algorithm",	/* bit  8                        */
	"nc",		/* bit  9                        */
	"cnonce",	/* bit 10                        */
	"domain",	/* bit 11 (optional)             */
};

#define DIGEST_SEEN_TYPE	(1 << 0)
#define DIGEST_SEEN_USERNAME	(1 << 1)
#define DIGEST_SEEN_REALM	(1 << 2)
#define DIGEST_SEEN_NONCE	(1 << 3)
#define DIGEST_SEEN_RESPONSE	(1 << 5)
#define DIGEST_SEEN_QOP		(1 << 7)
#define DIGEST_SEEN_ALGORITHM	(1 << 8)
#define DIGEST_SEEN_NC		(1 << 9)
#define DIGEST_SEEN_CNONCE	(1 << 10)

/* minimum required fields for qop=auth */
#define DIGEST_REQUIRED (DIGEST_SEEN_TYPE | DIGEST_SEEN_USERNAME | \
			 DIGEST_SEEN_REALM | DIGEST_SEEN_NONCE | \
			 DIGEST_SEEN_RESPONSE)

#define PEND_NAME_EQ	-1
#define PEND_DELIM	-2

/*
 * lws_digest_make_nonce() - generate a verifiable nonce for WWW-Authenticate
 *
 * Produces: rand_hex ":" hex( H( rand_hex ":" timestamp ":" vhost_secret_hex ) )
 *
 * The random prefix ensures each issued nonce is unique even within the same
 * second.  The hash binds the prefix to the timestamp and the per-vhost secret,
 * making the nonce unguessable without knowledge of the secret.
 */
static void
lws_digest_ensure_vhost_key(struct lws *wsi)
{
	uint8_t *k = wsi->a.vhost->http.http_digest_auth_key;

	/* lazy-init: generate a random per-vhost secret once */
	if (!k[0] && !k[1] && !k[2] && !k[3])
		lws_get_random(wsi->a.context, k, sizeof(wsi->a.vhost->http.http_digest_auth_key));
}

/*
 * nonce = rand_hex ":" hex( H( rand_hex ":" timestamp ":" secret_hex ) )
 *
 * The 4-byte random prefix is embedded in the nonce string so the verifier
 * can recover it and recompute the hash.  This guarantees uniqueness even
 * within the same second, preventing nonce reuse.
 */
static int
lws_digest_make_nonce(struct lws *wsi, int algo,
		      char *nonce_out, size_t nonce_len)
{
	uint8_t rand_bytes[4], digest[LWS_GENHASH_LARGEST];
	char rand_hex[9], secret_hex[33], plain[96];
	struct lws_genhash_ctx hc;
	size_t hash_hex_len;
	time_t t;
	int n;

	lws_digest_ensure_vhost_key(wsi);
	lws_get_random(wsi->a.context, rand_bytes, sizeof(rand_bytes));
	lws_hex_from_byte_array(rand_bytes, sizeof(rand_bytes),
				rand_hex, sizeof(rand_hex));
	lws_hex_from_byte_array(wsi->a.vhost->http.http_digest_auth_key,
				sizeof(wsi->a.vhost->http.http_digest_auth_key),
				secret_hex, sizeof(secret_hex));

	time(&t);
	n = lws_snprintf(plain, sizeof(plain), "%s:%lu:%s",
			 rand_hex, (unsigned long)t, secret_hex);

	if (lws_genhash_init(&hc, algo) ||
	    lws_genhash_update(&hc, plain, (size_t)n) ||
	    lws_genhash_destroy(&hc, digest)) {
		lws_genhash_destroy(&hc, NULL);
		return -1;
	}

	/* nonce = rand_hex ":" hash_hex */
	hash_hex_len = lws_genhash_size(algo) * 2;
	if (nonce_len < 9 + 1 + hash_hex_len + 1)
		return -1;
	lws_snprintf(nonce_out, nonce_len, "%s:", rand_hex);
	lws_hex_from_byte_array(digest, lws_genhash_size(algo),
				nonce_out + 9, nonce_len - 9);
	return 0;
}

/*
 * lws_digest_verify_nonce() - check a client-supplied nonce is one we issued
 *
 * The nonce string format is: rand_hex ":" hash_hex
 * We extract rand_hex, then recompute H(rand_hex:ts:secret) for timestamps
 * t, t-1, t-2 and compare with the hash_hex portion.
 *
 * Returns 0 if valid, -1 if stale or malformed.
 */
static int
lws_digest_verify_nonce(struct lws *wsi, int algo, const char *nonce_str)
{
	uint8_t digest[LWS_GENHASH_LARGEST], nonce_hash[LWS_GENHASH_LARGEST];
	char secret_hex[33], plain[96];
	struct lws_genhash_ctx hc;
	const char *colon, *hash_hex;
	size_t rand_len, hash_len;
	time_t t;
	int m, n;

	/* split "rand_hex:hash_hex" at the first colon */
	colon = strchr(nonce_str, ':');
	if (!colon)
		return -1;

	rand_len = (size_t)(colon - nonce_str);
	if (rand_len < 1 || rand_len > 16)
		return -1;

	hash_hex = colon + 1;
	hash_len = lws_genhash_size(algo);

	/* decode the hash portion to bytes for comparison */
	if (lws_hex_len_to_byte_array(hash_hex, strlen(hash_hex),
				      nonce_hash, (int)sizeof(nonce_hash)) < 0)
		return -1;

	lws_hex_from_byte_array(wsi->a.vhost->http.http_digest_auth_key,
				sizeof(wsi->a.vhost->http.http_digest_auth_key),
				secret_hex, sizeof(secret_hex));

	/*
	 * Recompute H(rand_hex:timestamp:secret) for t, t-1, t-2 to tolerate
	 * slight clock drift between challenge and response.
	 */
	time(&t);
	for (m = 0; m >= -2; m--) {
		n = lws_snprintf(plain, sizeof(plain), "%.*s:%lu:%s",
				 (int)rand_len, nonce_str,
				 (unsigned long)(t + (long)m), secret_hex);

		if (lws_genhash_init(&hc, algo) ||
		    lws_genhash_update(&hc, plain, (size_t)n) ||
		    lws_genhash_destroy(&hc, digest)) {
			lws_genhash_destroy(&hc, NULL);
			return -1;
		}

		if (!lws_timingsafe_bcmp(digest, nonce_hash, (uint32_t)hash_len))
			return 0;
	}

	return -1;
}

/* nonce string: 8 rand hex + ':' + up to 64 hash hex + NUL = 74 bytes */
#define LWS_DIGEST_NONCE_LEN (LWS_GENHASH_LARGEST * 2 + 10)

/*
 * lws_unauthorised_digest_auth() - send HTTP 401 with two WWW-Authenticate
 * headers, one for MD5 and one for SHA-256, each with a fresh nonce.
 *
 * Pass stale=1 when the nonce expired (client should retry silently),
 * stale=0 for a genuine auth failure (browser will prompt for password).
 */
int
lws_unauthorised_digest_auth(struct lws *wsi, const char *realm, int stale)
{
	struct lws_context_per_thread *pt = &wsi->a.context->pt[(int)wsi->tsi];
	unsigned char *start = pt->serv_buf + LWS_PRE,
		      *p = start, *end = p + 2048;
	char nonce_md5[LWS_DIGEST_NONCE_LEN];
	char nonce_sha256[LWS_DIGEST_NONCE_LEN];
	const char *stale_str = stale ? "TRUE" : "FALSE";
	char buf[320];
	int n;

	if (lws_add_http_header_status(wsi, HTTP_STATUS_UNAUTHORIZED, &p, end))
		return -1;

	/* generate independent nonces for each algorithm */
	if (lws_digest_make_nonce(wsi, LWS_GENHASH_TYPE_MD5,
				  nonce_md5, sizeof(nonce_md5)))
		return -1;
	if (lws_digest_make_nonce(wsi, LWS_GENHASH_TYPE_SHA256,
				  nonce_sha256, sizeof(nonce_sha256)))
		return -1;

	/*
	 * First header: MD5 (no algorithm= means MD5 per RFC7616 §3.3).
	 * Matches browser / ONVIF client default.
	 */
	n = lws_snprintf(buf, sizeof(buf),
			 "Digest realm=\"%s\", qop=\"auth\", "
			 "nonce=\"%s\", stale=\"%s\"",
			 realm, nonce_md5, stale_str);
	if (lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_WWW_AUTHENTICATE,
					 (unsigned char *)buf, n, &p, end))
		return -1;

	/*
	 * Second header: SHA-256 (RFC7616 preferred algorithm).
	 */
	n = lws_snprintf(buf, sizeof(buf),
			 "Digest realm=\"%s\", qop=\"auth\", "
			 "nonce=\"%s\", algorithm=\"SHA-256\", stale=\"%s\"",
			 realm, nonce_sha256, stale_str);
	if (lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_WWW_AUTHENTICATE,
					 (unsigned char *)buf, n, &p, end))
		return -1;

	if (lws_add_http_header_content_length(wsi, 0, &p, end))
		return -1;
	if (lws_finalize_http_header(wsi, &p, end))
		return -1;

	n = lws_write(wsi, start, lws_ptr_diff_size_t(p, start),
		      LWS_WRITE_HTTP_HEADERS | LWS_WRITE_H2_STREAM_END);
	if (n < 0)
		return -1;

	return lws_http_transaction_completed(wsi);
}

/*
 * lws_check_digest_auth() - verify an Authorization: Digest ... header
 *
 * Parses the header, validates the nonce, retrieves H(A1) via callback, then
 * computes the expected RFC7616 response and compares to the client's value.
 *
 * RFC7616 §3.4:
 *   A1   = unq(username) ":" unq(realm) ":" passwd
 *   A2   = Method ":" digestURI                        (qop=auth)
 *   KD(s,d) = H(concat(s,":",d))
 *   response = KD(H(A1), unq(nonce) ":" nc ":" unq(cnonce) ":" unq(qop) ":" H(A2))
 *            = H(HA1 ":" nonce ":" nc ":" cnonce ":" qop ":" HA2)
 *
 * For compatibility (no qop):
 *   response = KD(H(A1), unq(nonce) ":" H(A2))
 */
enum lws_check_basic_auth_results
lws_check_digest_auth(struct lws *wsi, const char *realm_str)
{
	char b64[640], username[64], realm[64], nonce_hex[LWS_DIGEST_NONCE_LEN];
	char nc_str[9], cnonce[64], uri_field[256];
	uint8_t response_bytes[LWS_GENHASH_LARGEST];
	uint8_t ha2[LWS_GENHASH_LARGEST], expected[LWS_GENHASH_LARGEST];
	char ha1_hex[LWS_GENHASH_LARGEST * 2 + 1];
	char ha2_hex[LWS_GENHASH_LARGEST * 2 + 1];
	struct lws_digest_auth_req req;
	struct lws_genhash_ctx hc;
	struct lws_tokenize ts;
	lws_tokenize_elem e;
	int seen = 0, pend = PEND_NAME_EQ, skipping = 0;
	int m, ml, fi, n, algo = LWS_GENHASH_TYPE_MD5;
	int has_qop = 0, resp_hex_len = 0;
	size_t hash_len;
	char *uri_ptr;
	int uri_len;
	char a2_plain[320], final_plain[512]; /* SHA-256: 64+64+8+64+extras > 200 */
	const char *method_name;

	static const char * const method_names[] = {
		"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"
	};
	static const enum lws_token_indexes method_tokens[] = {
		WSI_TOKEN_GET_URI, WSI_TOKEN_POST_URI, WSI_TOKEN_PUT_URI,
		WSI_TOKEN_DELETE_URI, WSI_TOKEN_HEAD_URI,
		WSI_TOKEN_OPTIONS_URI, WSI_TOKEN_PATCH_URI
	};

	if (!realm_str)
		realm_str = "lws";

	/* Did client send an Authorization header? */
	ml = lws_hdr_total_length(wsi, WSI_TOKEN_HTTP_AUTHORIZATION);
	if (ml) {
		/* Disallow fragmented headers */
		fi = wsi->http.ah->frag_index[WSI_TOKEN_HTTP_AUTHORIZATION];
		if (wsi->http.ah->frags[fi].nfrag) {
			lwsl_wsi_err(wsi, "fragmented auth header not allowed\n");
			return LCBA_FAILED_AUTH;
		}

		m = lws_hdr_copy(wsi, b64, sizeof(b64) - 1,
				  WSI_TOKEN_HTTP_AUTHORIZATION);
		if (m < 7) {
			lwsl_wsi_err(wsi, "auth header too short\n");
			return LCBA_END_TRANSACTION;
		}
		b64[m] = '\0';
	} else {
		/*
		 * No Authorization header — browsers cannot set custom headers
		 * on WebSocket connections, so the JS client may pass digest
		 * auth via a URL query param: ?auth=<url-encoded-digest-header>
		 */
		m = lws_get_urlarg_by_name_safe(wsi, "auth", b64,
						 (int)sizeof(b64) - 1);
		if (m < 7)
			return LCBA_FAILED_AUTH;
		b64[m] = '\0';
	}

	/* If it's Basic auth, not our job */
	if (!strncasecmp(b64, "Basic ", 6))
		return LCBA_FAILED_AUTH;

	/* Zero out storage */
	memset(username, 0, sizeof(username));
	memset(realm, 0, sizeof(realm));
	memset(nonce_hex, 0, sizeof(nonce_hex));
	memset(nc_str, 0, sizeof(nc_str));
	memset(cnonce, 0, sizeof(cnonce));
	memset(uri_field, 0, sizeof(uri_field));
	memset(response_bytes, 0, sizeof(response_bytes));

	/*
	 * Parse the Authorization: Digest ... header using lws_tokenize.
	 * Format (RFC7616 §3.4):
	 *   Authorization: Digest username="...", realm="...", nonce="...",
	 *     uri="...", algorithm=MD5, qop=auth, nc=00000001,
	 *     cnonce="...", response="..."
	 */
	lws_tokenize_init(&ts, b64, LWS_TOKENIZE_F_MINUS_NONTERM |
				    LWS_TOKENIZE_F_NO_INTEGERS |
				    LWS_TOKENIZE_F_RFC7230_DELIMS);
	ts.len = (size_t)m;

	do {
		e = lws_tokenize(&ts);
		switch (e) {

		case LWS_TOKZE_TOKEN:
			if (skipping)
				break;

			if (pend == 8) {
				/* algorithm value (unquoted): MD5 or SHA-256 */
				if (!strncasecmp(ts.token, "SHA-256", ts.token_len) ||
				    !strncasecmp(ts.token, "SHA256", ts.token_len))
					algo = LWS_GENHASH_TYPE_SHA256;
				else if (!strncasecmp(ts.token, "MD5", ts.token_len))
					algo = LWS_GENHASH_TYPE_MD5;
				else {
					lwsl_wsi_notice(wsi, "unsupported algorithm '%.*s'\n",
							(int)ts.token_len, ts.token);
					return LCBA_END_TRANSACTION;
				}
				pend = PEND_DELIM;
				break;
			}

			if (pend == 7) {
				/* qop value (unquoted): auth */
				if (!strncasecmp(ts.token, "auth", ts.token_len))
					has_qop = 1;
				pend = PEND_DELIM;
				break;
			}

			if (pend == 9) {
				/* nc value (unquoted hex) */
				if (ts.token_len < (int)sizeof(nc_str))
					lws_strncpy(nc_str, ts.token,
						    sizeof(nc_str));
				pend = PEND_DELIM;
				break;
			}

			/* Must start with "Digest" keyword */
			if (!strncasecmp(ts.token, "Digest", ts.token_len)) {
				if (seen & DIGEST_SEEN_TYPE) {
					lwsl_wsi_notice(wsi, "repeated Digest keyword\n");
					return LCBA_END_TRANSACTION;
				}
				seen |= DIGEST_SEEN_TYPE;
				pend = PEND_NAME_EQ;
				break;
			}

			if (!(seen & DIGEST_SEEN_TYPE)) {
				skipping = 1;
				break;
			}
			break;

		case LWS_TOKZE_TOKEN_NAME_EQUALS:
			if (skipping)
				break;
			if (!(seen & DIGEST_SEEN_TYPE) || pend != PEND_NAME_EQ) {
				lwsl_wsi_notice(wsi, "disordered digest header\n");
				return LCBA_END_TRANSACTION;
			}

			for (n = 0; n < (int)LWS_ARRAY_SIZE(digest_toks); n++)
				if (!strncasecmp(ts.token, digest_toks[n],
						 (size_t)ts.token_len) &&
				    strlen(digest_toks[n]) == (size_t)ts.token_len)
					break;

			if (n == (int)LWS_ARRAY_SIZE(digest_toks)) {
				/* unknown field — skip its value */
				pend = PEND_DELIM;
				break;
			}

			if (seen & (1 << n)) {
				lwsl_wsi_notice(wsi, "duplicate digest field '%s'\n",
						digest_toks[n]);
				return LCBA_END_TRANSACTION;
			}

			seen |= (1 << n);
			pend = n;
			break;

		case LWS_TOKZE_QUOTED_STRING:
			if (skipping)
				break;
			if (pend < 0) {
				lwsl_wsi_notice(wsi, "unexpected quoted string\n");
				return LCBA_END_TRANSACTION;
			}

			switch (pend) {
			case 1: /* username */
				if (ts.token_len >= (int)sizeof(username))
					return LCBA_END_TRANSACTION;
				lws_strncpy(username, ts.token, sizeof(username));
				username[ts.token_len] = '\0';
				break;
			case 2: /* realm */
				if (ts.token_len >= (int)sizeof(realm))
					return LCBA_END_TRANSACTION;
				lws_strncpy(realm, ts.token, sizeof(realm));
				realm[ts.token_len] = '\0';
				break;
			case 3: /* nonce — store as string; lws_digest_verify_nonce parses it */
				if (ts.token_len >= (int)sizeof(nonce_hex))
					return LCBA_END_TRANSACTION;
				lws_strncpy(nonce_hex, ts.token, sizeof(nonce_hex));
				nonce_hex[ts.token_len] = '\0';
				break;
			case 4: /* uri — store for A2 */
				if (ts.token_len >= (int)sizeof(uri_field))
					return LCBA_END_TRANSACTION;
				lws_strncpy(uri_field, ts.token, sizeof(uri_field));
				uri_field[ts.token_len] = '\0';
				break;
			case 5: /* response -- decoded now; exact length checked post-parse when algo is known */
				if (ts.token_len > LWS_GENHASH_LARGEST * 2)
					return LCBA_END_TRANSACTION;
				resp_hex_len = (int)ts.token_len;
				if (lws_hex_len_to_byte_array(ts.token,
						(size_t)ts.token_len,
						response_bytes,
						(int)sizeof(response_bytes)) < 0)
					return LCBA_END_TRANSACTION;
				break;
			case 6: /* opaque — ignored */
				break;
			case 7: /* qop quoted value */
				if (!strncasecmp(ts.token, "auth", ts.token_len))
					has_qop = 1;
				break;
			case 10: /* cnonce */
				if (ts.token_len >= (int)sizeof(cnonce))
					return LCBA_END_TRANSACTION;
				lws_strncpy(cnonce, ts.token, sizeof(cnonce));
				cnonce[ts.token_len] = '\0';
				break;
			}
			pend = PEND_DELIM;
			break;

		case LWS_TOKZE_DELIMITER:
			if (*ts.token == ',') {
				if (skipping) {
					skipping = 0;
					break;
				}
				if (pend != PEND_DELIM)
					return LCBA_END_TRANSACTION;
				pend = PEND_NAME_EQ;
				break;
			}
			if (*ts.token == ';') {
				e = LWS_TOKZE_ENDED;
				break;
			}
			break;

		case LWS_TOKZE_ENDED:
			break;

		default:
			return LCBA_END_TRANSACTION;
		}

	} while (e > 0);

	if (e != LWS_TOKZE_ENDED)
		return LCBA_END_TRANSACTION;

	/* verify required fields were present */
	if ((seen & DIGEST_REQUIRED) != DIGEST_REQUIRED) {
		lwsl_wsi_notice(wsi, "missing required digest fields 0x%x\n", seen);
		return LCBA_FAILED_AUTH;
	}

	/*
	 * Verify response hash length now that algo is definitively known.
	 * This deferred check handles the case where algorithm= appears after
	 * response= in the Authorization header (RFC7616 does not mandate
	 * field ordering).
	 */
	if (resp_hex_len != (int)lws_genhash_size(algo) * 2) {
		lwsl_wsi_notice(wsi, "response length %d wrong for algo\n",
				resp_hex_len);
		return LCBA_END_TRANSACTION;
	}

	/*
	 * Note: nonce count (nc) is included in the response hash but is not
	 * tracked across requests.  RFC7616 recommends per-nonce nc state to
	 * prevent replays, but this implementation is stateless.  The short
	 * nonce lifetime (~3 seconds) provides a bounded replay window.
	 */

	/* verify nonce is one we issued (timestamp window t .. t-2) */
	hash_len = lws_genhash_size(algo);
	if (lws_digest_verify_nonce(wsi, algo, nonce_hex)) {
		lwsl_wsi_notice(wsi, "nonce verification failed (stale)\n");
		return LCBA_STALE_NONCE;
	}

	/*
	 * Retrieve H(A1) from the application via callback.
	 * The application fills req.ha1[] with H(username:realm:password).
	 */
	memset(&req, 0, sizeof(req));
	req.username = username;
	req.realm = realm_str;
	req.algo = algo;

	if (wsi->a.protocol->callback(wsi, LWS_CALLBACK_HTTP_DIGEST_GET_HA1,
				       wsi->user_space, &req, 0)) {
		lwsl_wsi_notice(wsi, "digest auth: user '%s' not found\n", username);
		return LCBA_FAILED_AUTH;
	}

	if (!req.ha1_set) {
		/*
		 * Callback returned 0 but didn't fill ha1[].  This is a
		 * programming error in the application callback — treat it as
		 * a server-side error rather than accepting a zeroed hash.
		 */
		lwsl_wsi_err(wsi, "digest auth callback did not set ha1\n");
		return LCBA_END_TRANSACTION;
	}

	/* compute HA1 hex string from callback result */
	lws_hex_from_byte_array(req.ha1, hash_len,
				ha1_hex, sizeof(ha1_hex));

	/*
	 * Determine the HTTP method for A2.
	 * A2 = Method ":" digestURI
	 */
	if (lws_http_get_uri_and_method(wsi, &uri_ptr, &uri_len) < 0) {
		lwsl_wsi_notice(wsi, "could not get URI/method\n");
		return LCBA_END_TRANSACTION;
	}

	method_name = "GET"; /* default fallback */
	for (n = 0; n < (int)LWS_ARRAY_SIZE(method_tokens); n++) {
		if (lws_hdr_total_length(wsi, method_tokens[n])) {
			method_name = method_names[n];
			break;
		}
	}

	/*
	 * Use the URI from the Authorization header if provided (as per RFC7616).
	 * RFC7616 §3.4.1 requires the digest uri to match the request URI.
	 * We compare only the path component (before '?') so that query strings
	 * added by the client (e.g. the ?auth= WebSocket workaround) don't
	 * cause a false mismatch.
	 */
	if (uri_field[0]) {
		const char *qs = memchr(uri_ptr, '?', (size_t)uri_len);
		int path_len = qs ? (int)(qs - uri_ptr) : uri_len;

		if ((int)strlen(uri_field) != path_len ||
		    strncmp(uri_field, uri_ptr, (size_t)path_len)) {
			lwsl_wsi_notice(wsi,
				"digest uri mismatch: auth='%s' req='%.*s'\n",
				uri_field, uri_len, uri_ptr);
			return LCBA_FAILED_AUTH;
		}
		n = lws_snprintf(a2_plain, sizeof(a2_plain), "%s:%s",
				 method_name, uri_field);
	} else
		n = lws_snprintf(a2_plain, sizeof(a2_plain), "%s:%.*s",
				 method_name, uri_len, uri_ptr);

	/* compute HA2 = H(A2) */
	if (lws_genhash_init(&hc, algo) ||
	    lws_genhash_update(&hc, a2_plain, (size_t)n) ||
	    lws_genhash_destroy(&hc, ha2)) {
		lws_genhash_destroy(&hc, NULL);
		return LCBA_END_TRANSACTION;
	}
	lws_hex_from_byte_array(ha2, hash_len, ha2_hex, sizeof(ha2_hex));

	/*
	 * Compute expected response:
	 *   qop=auth:  H( HA1 ":" nonce ":" nc ":" cnonce ":" "auth" ":" HA2 )
	 *   no qop:    H( HA1 ":" nonce ":" HA2 )
	 */
	if (has_qop)
		n = lws_snprintf(final_plain, sizeof(final_plain),
				 "%s:%s:%s:%s:auth:%s",
				 ha1_hex, nonce_hex,
				 nc_str[0] ? nc_str : "00000001",
				 cnonce[0] ? cnonce : "",
				 ha2_hex);
	else
		n = lws_snprintf(final_plain, sizeof(final_plain),
				 "%s:%s:%s", ha1_hex, nonce_hex, ha2_hex);

	if (lws_genhash_init(&hc, algo) ||
	    lws_genhash_update(&hc, final_plain, (size_t)n) ||
	    lws_genhash_destroy(&hc, expected)) {
		lws_genhash_destroy(&hc, NULL);
		return LCBA_END_TRANSACTION;
	}

	/* constant-time comparison to avoid timing side-channels (RFC7616 §5.6) */
	if (lws_timingsafe_bcmp(expected, response_bytes, (uint32_t)hash_len)) {
		lwsl_wsi_notice(wsi, "digest response mismatch for user '%s'\n",
				username);
		return LCBA_FAILED_AUTH;
	}

	/*
	 * Auth accepted: rewrite the Authorization header to just the username
	 * so downstream code can read it via lws_hdr_simple_ptr().
	 */
	lws_authorization_rewrite(wsi, username, strlen(username));

	lwsl_wsi_info(wsi, "digest auth accepted for '%s' (algo=%s)\n",
		      username,
		      algo == LWS_GENHASH_TYPE_SHA256 ? "SHA-256" : "MD5");

	return LCBA_CONTINUE;
}

#endif /* LWS_WITH_HTTP_DIGEST_AUTH */
