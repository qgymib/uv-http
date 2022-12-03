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

static void _test_echo_server_on_http_exit(uv_http_t* http)
{
    test_simple_server_t* ctx = container_of(http, test_simple_server_t, http);
    ASSERT_EQ_PTR(ctx, s_test_simple_server);
}

static void _test_echo_server_on_event(uv_http_conn_t* conn, uv_http_event_t evt,
    void* evt_data, void* arg)
{
    (void)evt_data;
    ASSERT_NE_PTR(conn, NULL);
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
        ASSERT_EQ_D32(uv_http_reply(conn, 200, hw, strlen(hw), NULL), 0);
    }
}

TEST_FIXTURE_SETUP(simple_server)
{
    s_test_simple_server = malloc(sizeof(test_simple_server_t));
    memset(s_test_simple_server, 0, sizeof(*s_test_simple_server));

    ASSERT_EQ_D32(uv_loop_init(&s_test_simple_server->loop), 0);
    ASSERT_EQ_D32(uv_http_init(&s_test_simple_server->http, &s_test_simple_server->loop), 0);
}

TEST_FIXTURE_TEAREDOWN(simple_server)
{
    uv_http_exit(&s_test_simple_server->http, _test_echo_server_on_http_exit);

    ASSERT_EQ_D32(uv_run(&s_test_simple_server->loop, UV_RUN_DEFAULT), 0);
    ASSERT_EQ_D32(uv_loop_close(&s_test_simple_server->loop), 0);

    free(s_test_simple_server);
    s_test_simple_server = NULL;
}

TEST_F(simple_server, 1)
{
    const char* url = "http://127.0.0.1:5000";
    ASSERT_EQ_D32(uv_http_listen(&s_test_simple_server->http, url, _test_echo_server_on_event, s_test_simple_server), 0);

    char buffer[64];
    int port;
    ASSERT_EQ_D32(uv_http_get_listen_address(&s_test_simple_server->http, buffer, sizeof(buffer), &port), 0);
    ASSERT_EQ_STR(buffer, "127.0.0.1");
    ASSERT_NE_D32(port, 0);

    uv_run(&s_test_simple_server->loop, UV_RUN_DEFAULT);
}
