#include "uv-http.h"
#include <cutest.h>
#include <stdlib.h>
#include <string.h>

typedef struct test_file_server
{
    uv_loop_t   loop;
    uv_http_t   http;
    char        exe_path[PATH_MAX];
} test_file_server_t;

static test_file_server_t* s_test_file_server = NULL;

static void s_test_file_server_on_listen(uv_http_conn_t* conn, uv_http_event_t evt,
    void* evt_data, void* arg)
{
    (void)arg;
    if (evt == UV_HTTP_MESSAGE)
    {
        uv_http_message_t* msg = evt_data;
        if (strcmp(msg->url.ptr, "/exit") == 0)
        {
            uv_stop(&s_test_file_server->loop);
            return;
        }

        size_t exe_path_size = sizeof(s_test_file_server->exe_path);
        ASSERT_EQ_D32(uv_exepath(s_test_file_server->exe_path, &exe_path_size), 0);

        uv_http_serve_cfg_t cfg; memset(&cfg, 0, sizeof(cfg));
        cfg.root_path = s_test_file_server->exe_path;

        ASSERT_EQ_D32(uv_http_serve_file(conn, msg, &cfg), 0);
    }
}

TEST_FIXTURE_SETUP(file_server)
{
    s_test_file_server = malloc(sizeof(test_file_server_t));

    ASSERT_EQ_D32(uv_loop_init(&s_test_file_server->loop), 0);
    ASSERT_EQ_D32(uv_http_init(&s_test_file_server->http, &s_test_file_server->loop), 0);
}

TEST_FIXTURE_TEAREDOWN(file_server)
{
    uv_http_exit(&s_test_file_server->http, NULL);
    ASSERT_EQ_D32(uv_run(&s_test_file_server->loop, UV_RUN_DEFAULT), 0);
    ASSERT_EQ_D32(uv_loop_close(&s_test_file_server->loop), 0);

    free(s_test_file_server);
    s_test_file_server = NULL;
}

TEST_F(file_server, 0)
{
    const char* url = "http://127.0.0.1:5000";
    ASSERT_EQ_D32(uv_http_listen(&s_test_file_server->http, url, s_test_file_server_on_listen, NULL), 0);

    uv_run(&s_test_file_server->loop, UV_RUN_DEFAULT);
}
