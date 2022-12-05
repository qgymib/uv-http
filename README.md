# uv-http

A http client/server implemention for libuv.

## Introduction

uv-http is a http networking for C/C++ with libuv backend support. It is fully event-driven, non-blocking, even for file operation.

## Integration 

There are two way to integration uv-http.

### CMake

The recommand way is use CMake. Add following code to your CMakeLists.txt:

```cmake
add_subdirectory(path/to/uv-http)
target_link_libraries(TARGET_NAME private uvhttp)
```

That's all.

### Manual

1. Copy `uv-http.h` and `uv-http.c` to your build tree.
2. `uv-http` require [libuv](https://github.com/libuv/libuv) and [llhttp](https://github.com/nodejs/llhttp), be sure `uv-http` can find them.

## Quick start

```c

static void cb(uv_http_conn_t* conn, int evt, void* evt_data, void* arg) {
    if (evt == UV_HTTP_MESSAGE) {
        uv_http_message_t* msg = evt_data;
        uv_http_serve_cfg_t cfg = { .root_path = "." };
        uv_http_serve_dir(conn, msg, &cfg);
        return;
    }
}

int main(int argc, char* argv[]) {
    uv_loop_t loop;
    uv_loop_init(&loop);

    uv_http_t http;
    uv_http_init(&http, &loop);

    uv_http_listen(&http, "http://0.0.0.0:5000", cb, NULL);
    return uv_run(&loop, UV_RUN_DEFAULT);
}
```
