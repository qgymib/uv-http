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
    return cutest_run_tests(argc, argv, NULL);
}
