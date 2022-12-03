#include <uv.h>
#include <cutest.h>
#include <stdlib.h>

static void _at_exit(void)
{
    uv_library_shutdown();
}

int main(int argc, char* argv[])
{
    atexit(_at_exit);
    argv = uv_setup_args(argc, argv);
    return cutest_run_tests(argc, argv, NULL);
}
