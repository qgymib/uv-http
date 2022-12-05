#include "uv-http.h"
#include "test.h"
#include "utils/fs.h"
#include <stdlib.h>
#include <string.h>

typedef struct test_file_server
{
    uv_loop_t       loop;
    uv_http_t       http;

    void*           exe_dat;
    size_t          exe_len;
    char            exe_path[PATH_MAX];
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

        uv_http_serve_cfg_t cfg; memset(&cfg, 0, sizeof(cfg));
        cfg.root_path = s_test_file_server->exe_path;
        cfg.mime_types = "=text/plain; charset=utf-8";
        cfg.fs = uv_http_test_new_fs();

        ASSERT_EQ_D32(uv_http_serve_file(conn, msg, &cfg), 0);
    }
}

static void s_test_file_server_on_connect(uv_http_conn_t* conn, uv_http_event_t evt,
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
        ASSERT_EQ_U32(msg->body.len, s_test_file_server->exe_len);
        ASSERT_EQ_D32(memcmp(msg->body.ptr, s_test_file_server->exe_dat, msg->body.len), 0);

        ASSERT_EQ_D32(0, uv_http_query(conn, "POST", "/exit", NULL, NULL));
        return;
    }
}

TEST_FIXTURE_SETUP(file_server)
{
    s_test_file_server = malloc(sizeof(test_file_server_t));

    ASSERT_EQ_D32(uv_loop_init(&s_test_file_server->loop), 0);
    ASSERT_EQ_D32(uv_http_init(&s_test_file_server->http, &s_test_file_server->loop), 0);

	size_t exe_path_size = sizeof(s_test_file_server->exe_path);
	ASSERT_EQ_D32(uv_exepath(s_test_file_server->exe_path, &exe_path_size), 0);

    uv_http_fs_t* fs = uv_http_test_new_fs();
    ASSERT_EQ_D32(fs->stat(fs, s_test_file_server->exe_path, &s_test_file_server->exe_len, NULL), UV_HTTP_FS_READ | UV_HTTP_FS_WRITE);
    s_test_file_server->exe_dat = malloc(s_test_file_server->exe_len);

    void* fd = fs->open(fs, s_test_file_server->exe_path, UV_HTTP_FS_READ);
    ASSERT_NE_PTR(fd, NULL);
    ASSERT_EQ_D32(fs->read(fs, fd, s_test_file_server->exe_dat, s_test_file_server->exe_len), s_test_file_server->exe_len);

    fs->close(fs, fd);
    fs->release(fs);
}

TEST_FIXTURE_TEAREDOWN(file_server)
{
    uv_http_exit(&s_test_file_server->http, NULL);
    ASSERT_EQ_D32(uv_run(&s_test_file_server->loop, UV_RUN_DEFAULT), 0);
    ASSERT_EQ_D32(uv_loop_close(&s_test_file_server->loop), 0);

    free(s_test_file_server->exe_dat);
    s_test_file_server->exe_dat = NULL;
    s_test_file_server->exe_len = 0;

    free(s_test_file_server);
    s_test_file_server = NULL;
}

TEST_F(file_server, 0)
{
    /* Start server. */
    const char* url = "http://127.0.0.1:0";
    ASSERT_EQ_D32(uv_http_listen(&s_test_file_server->http, url, s_test_file_server_on_listen, NULL), 0);

    /* Start client. */
    char buffer[128];
    ASSERT_LT_D32(0, uv_http_get_listen_url(&s_test_file_server->http,
        buffer, sizeof(buffer)));
    ASSERT_EQ_D32(0, uv_http_connect(&s_test_file_server->http, buffer, 
        s_test_file_server_on_connect, NULL));

    uv_run(&s_test_file_server->loop, UV_RUN_DEFAULT);
}
