#include "uv-http.h"
#include "test.h"
#include "utils/fs.h"
#include <stdlib.h>
#include <string.h>

typedef struct test_dir_server
{
	uv_loop_t			loop;
	uv_http_t			http;
	uv_http_serve_cfg_t	cfg;
} test_dir_server_t;

static test_dir_server_t* s_test_dir_server = NULL;

static void s_test_dir_server_on_listen(uv_http_conn_t* conn, uv_http_event_t evt,
	void* evt_data, void* arg)
{
	(void)arg;
	if (evt == UV_HTTP_MESSAGE)
	{
		uv_http_message_t* msg = evt_data;
		if (strcmp(msg->url.ptr, "/exit") == 0)
		{
			uv_stop(&s_test_dir_server->loop);
			return;
		}

		ASSERT_EQ_D32(uv_http_serve_dir(conn, msg, &s_test_dir_server->cfg), 0);
		return;
	}
}

static void s_test_dir_server_on_connect(uv_http_conn_t* conn, uv_http_event_t evt,
	void* evt_data, void* arg)
{
	(void)arg;
	if (evt == UV_HTTP_CONNECT)
	{
		ASSERT_EQ_D32(0, uv_http_query(conn, "GET", "/", NULL, NULL));
		return;
	}

	if (evt == UV_HTTP_MESSAGE)
	{
		uv_http_message_t* msg = evt_data;
		ASSERT_NE_PTR(strstr(msg->body.ptr, "Index of /"), NULL);
		ASSERT_EQ_D32(0, uv_http_query(conn, "POST", "/exit", NULL, NULL));
		return;
	}
}

TEST_FIXTURE_SETUP(dir_server)
{
	s_test_dir_server = malloc(sizeof(test_dir_server_t));

	ASSERT_EQ_D32(uv_loop_init(&s_test_dir_server->loop), 0);
	ASSERT_EQ_D32(uv_http_init(&s_test_dir_server->http, &s_test_dir_server->loop), 0);

	memset(&s_test_dir_server->cfg, 0, sizeof(s_test_dir_server->cfg));
	s_test_dir_server->cfg.root_path = ".";
}

TEST_FIXTURE_TEAREDOWN(dir_server)
{
	uv_http_exit(&s_test_dir_server->http, NULL);
	ASSERT_EQ_D32(uv_run(&s_test_dir_server->loop, UV_RUN_DEFAULT), 0);
	ASSERT_EQ_D32(uv_loop_close(&s_test_dir_server->loop), 0);

	free(s_test_dir_server);
	s_test_dir_server = NULL;
}

TEST_F(dir_server, 0)
{
	const char* url = "http://127.0.0.1:5000";

	ASSERT_EQ_D32(0, uv_http_listen(&s_test_dir_server->http, url,
		s_test_dir_server_on_listen, NULL));

	char buffer[128];
	ASSERT_LT_D32(0, uv_http_get_listen_url(&s_test_dir_server->http,
		buffer, sizeof(buffer)));
	ASSERT_EQ_D32(0, uv_http_connect(&s_test_dir_server->http, buffer,
		s_test_dir_server_on_connect, NULL));

	uv_run(&s_test_dir_server->loop, UV_RUN_DEFAULT);
}
