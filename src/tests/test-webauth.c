/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Include the service to exercise its actual internal handlers. The renamed
 * entry point is never called: these tests need no D-Bus, root or VPN server. */
int service_main (int argc, char *argv[]);
#define main service_main
#include "../nm-openvpn-service.c"
#undef main

static void
test_parse_webauth (void)
{
	gs_free char *kind = NULL;
	gs_free char *flags = NULL;
	gs_free char *payload = NULL;
	const char *url = "https://vpn.example:8443/login?state=a:b&next=https://idp.example/";
	gs_free char *message = g_strconcat ("WEB_AUTH:external:", url, NULL);

	g_assert_true (parse_infomsg (message, &kind, &flags, &payload));
	g_assert_cmpstr (kind, ==, "webauth");
	g_assert_cmpstr (flags, ==, "external");
	g_assert_cmpstr (payload, ==, url);
}

static void
test_parse_empty_flags (void)
{
	gs_free char *kind = NULL;
	gs_free char *flags = NULL;
	gs_free char *payload = NULL;

	g_assert_true (parse_infomsg ("WEB_AUTH::https://vpn.example/", &kind, &flags, &payload));
	g_assert_cmpstr (flags, ==, "");
	g_assert_cmpstr (payload, ==, "https://vpn.example/");
}

static void
test_parse_legacy (void)
{
	gs_free char *kind = NULL;
	gs_free char *flags = NULL;
	gs_free char *payload = NULL;

	g_assert_true (parse_infomsg ("OPEN_URL:https://vpn.example:443/", &kind, &flags, &payload));
	g_assert_cmpstr (kind, ==, "webauth");
	g_assert_null (flags);
	g_assert_cmpstr (payload, ==, "https://vpn.example:443/");
}

static void
test_parse_text (void)
{
	gs_free char *kind = NULL;
	gs_free char *flags = NULL;
	gs_free char *payload = NULL;

	g_assert_true (parse_infomsg ("CR_TEXT:ER:Code: one time", &kind, &flags, &payload));
	g_assert_cmpstr (kind, ==, "crtext");
	g_assert_cmpstr (flags, ==, "ER");
	g_assert_cmpstr (payload, ==, "Code: one time");
}

static void
test_parse_invalid (void)
{
	const char *messages[] = { "", "OTHER:x:y", "WEB_AUTH:external", "CR_TEXT:R", NULL };
	guint i;

	for (i = 0; messages[i]; i++) {
		gs_free char *kind = NULL;
		gs_free char *flags = NULL;
		gs_free char *payload = NULL;

		g_assert_false (parse_infomsg (messages[i], &kind, &flags, &payload));
		g_assert_null (kind);
		g_assert_null (flags);
		g_assert_null (payload);
	}
}

static void
test_cr_response (gconstpointer data)
{
	const char *response = data;
	int fds[2];
	GIOChannel *channel;
	gs_free char *encoded = NULL;
	gs_free char *expected = NULL;
	char buf[1024] = { 0 };
	ssize_t count;

	g_assert_cmpint (pipe (fds), ==, 0);
	channel = g_io_channel_unix_new (fds[1]);
	write_cr_response (channel, response);
	g_io_channel_unref (channel);
	close (fds[1]);
	count = read (fds[0], buf, sizeof (buf) - 1);
	close (fds[0]);
	g_assert_cmpint (count, >, 0);
	encoded = g_base64_encode ((const guchar *) response, strlen (response));
	expected = g_strdup_printf ("cr-response %s\n", encoded);
	g_assert_cmpstr (buf, ==, expected);
	/* User-controlled newlines must not become management commands. */
	g_assert_cmpuint (strcspn (buf, "\n"), ==, strlen (buf) - 1);
}

static void
test_log_redaction (void)
{
	g_assert_cmpstr (management_log_message (">INFOMSG:WEB_AUTH::https://vpn.example/?state=secret"),
	                 ==, ">INFOMSG:[redacted]");
	g_assert_cmpstr (management_log_message (">INFOMSG:OPEN_URL:https://vpn.example/?token=secret"),
	                 ==, ">INFOMSG:[redacted]");
	g_assert_cmpstr (management_log_message (">INFOMSG:CR_TEXT:R:secret"),
	                 ==, ">INFOMSG:[redacted]");
	g_assert_cmpstr (management_log_message (">HOLD:Waiting"), ==, ">HOLD:Waiting");
}

int
main (int argc, char **argv)
{
	g_test_init (&argc, &argv, NULL);
	g_test_add_func ("/webauth/log/redaction", test_log_redaction);
	g_test_add_func ("/webauth/parse/url-with-colons", test_parse_webauth);
	g_test_add_func ("/webauth/parse/empty-flags", test_parse_empty_flags);
	g_test_add_func ("/webauth/parse/legacy", test_parse_legacy);
	g_test_add_func ("/webauth/parse/text", test_parse_text);
	g_test_add_func ("/webauth/parse/invalid", test_parse_invalid);
	g_test_add_data_func ("/webauth/response/otp", "123456", test_cr_response);
	g_test_add_data_func ("/webauth/response/injection", "123\nquit\r\n", test_cr_response);
	g_test_add_data_func ("/webauth/response/empty", "", test_cr_response);
	return g_test_run ();
}
