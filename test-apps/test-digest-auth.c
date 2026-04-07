/*
 * libwebsockets-test-digest-auth
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * The person who associated a work with this deed has dedicated
 * the work to the public domain by waiving all of his or her rights
 * to the work worldwide under copyright law, including all related
 * and neighboring rights, to the extent allowed by law. You can copy,
 * modify, distribute and perform the work, even for commercial purposes,
 * all without asking permission.
 *
 * The test apps are intended to be adapted for use in your code, which
 * may be proprietary.  So unlike the library itself, they are licensed
 * Public Domain.
 *
 * Demonstrates RFC7616 HTTP Digest Authentication server-side using
 * LWSAUTHM_DIGEST_AUTH_CALLBACK on a mount.
 *
 * The LWS_CALLBACK_HTTP_DIGEST_GET_HA1 callback computes H(A1) =
 * H(username:realm:password) from an in-memory credential table.  Real
 * applications would look up a pre-hashed H(A1) from a database instead
 * of storing plaintext passwords.
 *
 * Build (requires -DLWS_WITH_HTTP_DIGEST_AUTH=1 at cmake time):
 *
 *   cmake .. -DLWS_WITH_HTTP_DIGEST_AUTH=1
 *   make libwebsockets-test-digest-auth
 *
 * Usage:
 *   libwebsockets-test-digest-auth [--port 7681] [--realm myrealm]
 *                                  [--user user:password] ...
 *
 * Test (MD5 -- the default):
 *   curl --digest -u testuser:testpass http://localhost:7681/
 *
 * Test (SHA-256 -- RFC7616 preferred algorithm):
 *   curl --digest --digest-algorithms SHA-256 \
 *        -u testuser:testpass http://localhost:7681/
 */

#include <libwebsockets.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

#define MAX_USERS	16
#define MAX_REALM	64

struct tda_pss {
	int	dummy; /* per-session state; expand as needed */
};

static int interrupted;

struct tda_user {
	char	username[64];
	char	password[64]; /* plaintext only for this test app; use pre-hashed H(A1) in production */
};

static struct tda_user	users[MAX_USERS];
static int		user_count;
static char		realm_str[MAX_REALM] = "lws-test";

static int
callback_http(struct lws *wsi, enum lws_callback_reasons reason,
	      void *user, void *in, size_t len)
{
	unsigned char buf[LWS_PRE + 2048], *start = buf + LWS_PRE,
		      *p = start, *end = start + sizeof(buf) - LWS_PRE;
	static const char body[] = "Digest authentication successful.\n";
	struct lws_digest_auth_req *req;
	struct lws_genhash_ctx hc;
	char a1[192];
	int n, i;

	switch (reason) {

	case LWS_CALLBACK_HTTP_DIGEST_GET_HA1:
		/*
		 * lws calls this when it needs H(A1) to verify a client's
		 * Authorization: Digest response.  req->username and
		 * req->realm identify the credential; req->algo specifies
		 * which hash function to use.  Fill req->ha1[] with the
		 * result of H(username ":" realm ":" password) and set
		 * req->ha1_set = 1, then return 0.  Return non-zero to
		 * reject the request with 401 (user not found).
		 */
		req = (struct lws_digest_auth_req *)in;

		for (i = 0; i < user_count; i++) {
			if (strcmp(users[i].username, req->username))
				continue;

			n = lws_snprintf(a1, sizeof(a1), "%s:%s:%s",
					 req->username, realm_str,
					 users[i].password);

			if (lws_genhash_init(&hc, req->algo) ||
			    lws_genhash_update(&hc, a1, (size_t)n) ||
			    lws_genhash_destroy(&hc, req->ha1)) {
				lws_genhash_destroy(&hc, NULL);
				return 1; /* hash failed */
			}
			req->ha1_set = 1;

			return 0; /* success */
		}

		return 1; /* user not found → 401 */

	case LWS_CALLBACK_HTTP:
		/*
		 * lws only reaches here after digest auth has been verified
		 * by the mount machinery.  Serve a minimal response.
		 */
		if (lws_add_http_header_status(wsi, HTTP_STATUS_OK, &p, end) ||
		    lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_CONTENT_TYPE,
					(unsigned char *)"text/plain", 10,
					&p, end) ||
		    lws_add_http_header_content_length(wsi,
					sizeof(body) - 1, &p, end) ||
		    lws_finalize_http_header(wsi, &p, end))
			return -1;

		if (lws_write(wsi, start, lws_ptr_diff_size_t(p, start),
			      LWS_WRITE_HTTP_HEADERS) < 0)
			return -1;

		if (lws_write(wsi, (unsigned char *)body, sizeof(body) - 1,
			      LWS_WRITE_HTTP) < 0)
			return -1;

		if (lws_http_transaction_completed(wsi))
			return -1;

		return 0;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static struct lws_protocols protocols[] = {
	{
		"http",
		callback_http,
		sizeof(struct tda_pss),
		0, 0, NULL, 0
	},
	LWS_PROTOCOL_LIST_TERM
};

static void
sigint_handler(int sig)
{
	interrupted = 1;
}

int
main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	struct lws_http_mount mount;
	struct lws_context *context;
	const char *p;
	int n = 0, logs = LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE;

	signal(SIGINT, sigint_handler);

	if ((p = lws_cmdline_option(argc, argv, "-d")))
		logs = atoi(p);
	lws_set_log_level(logs, NULL);
	lwsl_user("LWS RFC7616 Digest Auth example\n");

	if ((p = lws_cmdline_option(argc, argv, "--realm")))
		lws_strncpy(realm_str, p, sizeof(realm_str));

	/*
	 * Collect --user user:password entries from the command line.
	 * Plaintext passwords are used only for this demonstration.  In
	 * production, store pre-computed H(A1) = H(user:realm:pass) per
	 * algorithm and return it directly from the callback.
	 */
	for (n = 1; n < argc - 1 && user_count < MAX_USERS; n++) {
		const char *colon;

		if (strcmp(argv[n], "--user"))
			continue;

		colon = strchr(argv[n + 1], ':');
		if (!colon) {
			lwsl_err("--user: expected user:password\n");
			return 1;
		}
		lws_strncpy(users[user_count].username, argv[n + 1],
			    (size_t)(colon - argv[n + 1]) + 1);
		lws_strncpy(users[user_count].password, colon + 1,
			    sizeof(users[0].password));
		user_count++;
	}

	if (!user_count) {
		/* built-in credential for quick testing */
		lws_strncpy(users[0].username, "testuser",
			    sizeof(users[0].username));
		lws_strncpy(users[0].password, "testpass",
			    sizeof(users[0].password));
		user_count = 1;
		lwsl_user("No --user specified; using testuser:testpass\n");
	}

	memset(&mount, 0, sizeof(mount));
	mount.mountpoint		= "/";
	mount.protocol			= "http"; /* bind LWSMPRO_CALLBACK mount to our protocol */
	mount.origin_protocol		= LWSMPRO_CALLBACK;
	mount.mountpoint_len		= 1;
	mount.auth_mask			= LWSAUTHM_DIGEST_AUTH_CALLBACK;
	mount.digest_auth_realm		= realm_str;

	memset(&info, 0, sizeof info);
	info.port		= 7681;
	info.protocols		= protocols;
	info.mounts		= &mount;
	info.options		=
		LWS_SERVER_OPTION_HTTP_HEADERS_SECURITY_BEST_PRACTICES_ENFORCE;

	if ((p = lws_cmdline_option(argc, argv, "--port")))
		info.port = atoi(p);

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	lwsl_user("Listening on port %d, realm '%s'\n", info.port, realm_str);
	lwsl_user("  curl --digest -u testuser:testpass "
		  "http://localhost:%d/\n", info.port);

	n = 0;
	while (n >= 0 && !interrupted)
		n = lws_service(context, 0);

	lws_context_destroy(context);

	return 0;
}
