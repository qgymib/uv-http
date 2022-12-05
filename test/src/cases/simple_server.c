#include "uv-http.h"
#include "test.h"
#include <stdlib.h>
#include <string.h>

typedef struct test_simple_server
{
    uv_loop_t   loop;   /**< Event loop. */
    uv_http_t   http;   /**< HTTP server. */
} test_simple_server_t;

static test_simple_server_t* s_test_simple_server = NULL;

static void s_test_echo_server_on_http_exit(uv_http_t* http)
{
    test_simple_server_t* ctx = container_of(http, test_simple_server_t, http);
    ASSERT_EQ_PTR(ctx, s_test_simple_server);
}

static void s_test_echo_server_on_listen(uv_http_conn_t* conn, int evt,
    void* evt_data, void* arg)
{
    ASSERT_EQ_PTR(arg, s_test_simple_server);

    if (evt == UV_HTTP_MESSAGE)
    {
        uv_http_message_t* msg = evt_data;
        if (strcmp(msg->url.ptr, "/exit") == 0)
        {
            uv_stop(&s_test_simple_server->loop);
            return;
        }

        const char* hw = "hello world";
        ASSERT_EQ_D32(0, uv_http_reply(conn, 200, NULL, "%s", hw));
    }
}

static void s_test_echo_server_on_connect(uv_http_conn_t* conn, int evt,
    void* evt_data, void* arg)
{
    ASSERT_EQ_PTR(arg, s_test_simple_server);

    if (evt == UV_HTTP_CONNECT)
    {
        ASSERT_EQ_D32(0, uv_http_query(conn, "GET", "/", NULL, NULL));
        return;
    }

    if (evt == UV_HTTP_MESSAGE)
    {
        uv_http_message_t* msg = evt_data;
        ASSERT_EQ_STR(msg->body.ptr, "hello world");
        ASSERT_EQ_D32(0, uv_http_query(conn, "POST", "/exit", NULL, NULL));
        return;
    }
}

TEST_FIXTURE_SETUP(simple_server)
{
    s_test_simple_server = malloc(sizeof(test_simple_server_t));
    memset(s_test_simple_server, 0, sizeof(*s_test_simple_server));

    ASSERT_EQ_D32(0, uv_loop_init(&s_test_simple_server->loop));
    ASSERT_EQ_D32(0, uv_http_init(&s_test_simple_server->http, &s_test_simple_server->loop));
}

TEST_FIXTURE_TEAREDOWN(simple_server)
{
    uv_http_exit(&s_test_simple_server->http, s_test_echo_server_on_http_exit);

    ASSERT_EQ_D32(uv_run(&s_test_simple_server->loop, UV_RUN_DEFAULT), 0);
    ASSERT_EQ_D32(uv_loop_close(&s_test_simple_server->loop), 0);

    free(s_test_simple_server);
    s_test_simple_server = NULL;
}

TEST_F(simple_server, 1)
{
    /* Start server. */
    const char* url = "http://127.0.0.1:0";
    ASSERT_EQ_D32(0, uv_http_listen(&s_test_simple_server->http, url,
        s_test_echo_server_on_listen, s_test_simple_server));

    /* Start client. */
    char buffer[128];
    ASSERT_LT_D32(0, uv_http_get_listen_url(&s_test_simple_server->http,
        buffer, sizeof(buffer)));
    ASSERT_EQ_D32(0, uv_http_connect(&s_test_simple_server->http, buffer,
        s_test_echo_server_on_connect, s_test_simple_server));

    uv_run(&s_test_simple_server->loop, UV_RUN_DEFAULT);
}
