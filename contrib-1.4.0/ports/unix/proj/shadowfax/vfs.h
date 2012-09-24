#ifndef __TRANS_VFS_H__
#define __TRANS_VFS_H__

#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <stdio.h>
#include <unistd.h>
#include <limits.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif


#define VFS_IRWXU S_IRWXU
#define VFS_IRWXG S_IRWXG
#define VFS_IRWXO S_IRWXO
#define VFS_ISDIR S_ISDIR
#define VFS_ISREG S_ISREG

typedef struct 
{
    char * cwd;
    char * list_dir;
}vfs_t;

typedef struct stat vfs_stat_t;

typedef struct dirent vfs_dirent_t;

typedef FILE vfs_file_t;

typedef DIR vfs_dir_t;

vfs_t* vfs_openfs( void );
void vfs_closefs( vfs_t* fs );
vfs_file_t *vfs_open( vfs_t * fs, const char *arg, const char *mode);
size_t vfs_read( void *buf,int what, int BufferSize, vfs_file_t *fp );
size_t vfs_write(  void *buf,int what, int BufferSize, vfs_file_t *fp  );
int vfs_eof( vfs_file_t *fp );
int vfs_close( vfs_file_t *fp );
int vfs_stat( vfs_t*, const char *fname, vfs_stat_t *st );
char *vfs_getcwd( vfs_t* fs, void *x, int y );
vfs_dir_t    *vfs_opendir( vfs_t*, const char *dir );
vfs_dirent_t *vfs_readdir( vfs_dir_t *fd );
int vfs_closedir( vfs_dir_t *fd );
int vfs_mkdir( vfs_t* fs, const char *arg, mode_t mode );
int vfs_rmdir( vfs_t* fs, const char *arg );
int vfs_rename( vfs_t* fs, char *was, const char *arg );
int vfs_remove( vfs_t* fs, const char *arg );
int vfs_chdir( vfs_t* fs, const char *arg );
void vfs_mode_string (mode_t mode, char *str);

#ifdef __cplusplus
}
#endif

#endif
