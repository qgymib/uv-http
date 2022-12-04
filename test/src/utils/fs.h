#ifndef __UV_HTTP_TEST_UTILS_FS_H__
#define __UV_HTTP_TEST_UTILS_FS_H__

#include "uv-http.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Create a new filesystem instance.
 * @return	Filesystem instance.
 */
uv_http_fs_t* uv_http_test_new_fs(void);

#ifdef __cplusplus
}
#endif

#endif
