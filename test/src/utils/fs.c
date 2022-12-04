#include "fs.h"
#include "test.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>

typedef struct uv_http_fs_impl
{
	uv_http_fs_t	handle;
} uv_http_fs_impl_t;

static void s_uv_http_test_fs_on_release(struct uv_http_fs* self)
{
	uv_http_fs_impl_t* impl = container_of(self, uv_http_fs_impl_t, handle);
	free(impl);
}

static int s_uv_http_test_fs_on_stat(struct uv_http_fs* self, const char* path, size_t* size, time_t* mtime)
{
	(void)self;
#if defined(_WIN32)
	struct _stat st;
	if (_stat(path, &st) != 0)
	{
		return 0;
	}
	int is_dir = st.st_mode & _S_IFDIR;
#else
	struct stat st;
	if (stat(path, &st) != 0)
	{
		return 0;
	}
	int is_dir = S_ISDIR(st.st_mode);
#endif

	if (size != NULL)
	{
		*size = st.st_size;
	}
	if (mtime != NULL)
	{
		*mtime = st.st_mtime;
	}
	return UV_HTTP_FS_READ | UV_HTTP_FS_WRITE | (is_dir ? UV_HTTP_FS_DIR : 0);
}

static void s_uv_http_test_fs_on_ls(struct uv_http_fs* self, const char* path, void (*cb)(const char* path, void* arg), void* arg)
{
    (void)self;
#if defined(_WIN32)

	char fix_path[PATH_MAX];
	snprintf(fix_path, sizeof(fix_path), "%s/*", path);

    WIN32_FIND_DATAA find_data;
    HANDLE dp = FindFirstFileA(fix_path, &find_data);
    if (dp == INVALID_HANDLE_VALUE)
    {
        return;
    }

    do
    {
        if (strcmp(find_data.cFileName, ".") == 0 || strcmp(find_data.cFileName, "..") == 0)
        {
            continue;
        }
        cb(find_data.cFileName, arg);
    } while (FindNextFileA(dp, &find_data));

    FindClose(dp);

#else
    DIR* dir;
    struct dirent* dp;

    if ((dir = opendir(path)) == NULL)
    {
        return;
    }

    while ((dp = readdir(dir)) != NULL)
    {
        if (strcmp(dp->d_name, ".") == 0 || strcmp(dp->d_name, "..") == 0)
        {
            continue;
        }
        cb(dp->d_name, arg);
    }
    closedir(dir);
#endif
}

static void* s_uv_http_test_fs_on_open(struct uv_http_fs* self, const char* path, int flags)
{
	(void)self;
	const char* mode = flags == UV_HTTP_FS_READ ? "rb" : "a+b";

#if defined(_WIN32)
	FILE* f;
	if (fopen_s(&f, path, mode) != 0)
	{
		return NULL;
	}
	return (void*)f;
#else
	return (void*)fopen(path, mode);
#endif
}

static void s_uv_http_test_fs_on_close(struct uv_http_fs* self, void* fd)
{
	(void)self;
	fclose((FILE*)fd);
}

static int s_uv_http_test_fs_on_read(struct uv_http_fs* self, void* fd, void* buf, size_t size)
{
	(void)self;
	return (int)fread(buf, 1, size, (FILE*)fd);
}

static int s_uv_http_test_fs_on_write(struct uv_http_fs* self, void* fd, const void* buf, size_t size)
{
	(void)self;
	return (int)fwrite(buf, 1, size, (FILE*)fd);
}

static int s_uv_http_test_fs_on_seek(struct uv_http_fs* self, void* fd, size_t offset)
{
	(void)self;
	if (fseek(fd, (long)offset, SEEK_SET) != 0)
	{
		return uv_translate_sys_error(errno);
	}
	return 0;
}

uv_http_fs_t* uv_http_test_new_fs(void)
{
	uv_http_fs_impl_t* impl = malloc(sizeof(uv_http_fs_impl_t));
	assert(impl != NULL);
	memset(impl, 0, sizeof(*impl));

	impl->handle.release = s_uv_http_test_fs_on_release;
	impl->handle.stat = s_uv_http_test_fs_on_stat;
    impl->handle.ls = s_uv_http_test_fs_on_ls;
    impl->handle.open = s_uv_http_test_fs_on_open;
	impl->handle.close = s_uv_http_test_fs_on_close;
	impl->handle.read = s_uv_http_test_fs_on_read;
	impl->handle.write = s_uv_http_test_fs_on_write;
	impl->handle.seek = s_uv_http_test_fs_on_seek;

	return &impl->handle;
}
