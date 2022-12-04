/* Enable memory leak detection for windows. */
#if defined(_WIN32)
#define _CRTDBG_MAP_ALLOC
#include <stdlib.h>
#include <crtdbg.h>
#endif

#include <uv.h>
#include <cutest.h>
#include <stdlib.h>

static void _at_exit(void)
{
    uv_library_shutdown();
}

int main(int argc, char* argv[])
{
#if defined(_WIN32)
    _CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF);
#endif

    atexit(_at_exit);
    argv = uv_setup_args(argc, argv);
    return cutest_run_tests(argc, argv, NULL);
}
