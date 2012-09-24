#include "vfs.h"
#include "lwip/debug.h"

#include "lwip/stats.h"

#include "lwip/tcp.h"

#include "log.h"

#define MAX_PATH_BUFFER 4096

/* Set the 's' and 't' flags in file attributes string CHARS,
   according to the file mode BITS.  */

static void setst (mode_t bits, char *chars)
{
#ifdef S_ISUID
  if (bits & S_ISUID)
    {
      if (chars[3] != 'x')
    /* Set-uid, but not executable by owner.  */
    chars[3] = 'S';
      else
    chars[3] = 's';
    }
#endif
#ifdef S_ISGID
  if (bits & S_ISGID)
    {
      if (chars[6] != 'x')
    /* Set-gid, but not executable by group.  */
    chars[6] = 'S';
      else
    chars[6] = 's';
    }
#endif
#ifdef S_ISVTX
  if (bits & S_ISVTX)
    {
      if (chars[9] != 'x')
    /* Sticky, but not executable by others.  */
    chars[9] = 'T';
      else
    chars[9] = 't';
    }
#endif
}


/* Return a character indicating the type of file described by
   file mode BITS:
   'd' for directories
   'D' for doors
   'b' for block special files
   'c' for character special files
   'n' for network special files
   'm' for multiplexor files
   'M' for an off-line (regular) file
   'l' for symbolic links
   's' for sockets
   'p' for fifos
   'C' for contigous data files
   '-' for regular files
   '?' for any other file type.  */

static char ftypelet (mode_t bits)
{
#ifdef S_ISBLK
  if (S_ISBLK (bits))
    return 'b';
#endif
  if (S_ISCHR (bits))
    return 'c';
  if (S_ISDIR (bits))
    return 'd';
  if (S_ISREG (bits))
    return '-';
#ifdef S_ISFIFO
  if (S_ISFIFO (bits))
    return 'p';
#endif
#ifdef S_ISLNK
  if (S_ISLNK (bits))
    return 'l';
#endif
#ifdef S_ISSOCK
  if (S_ISSOCK (bits))
    return 's';
#endif
#ifdef S_ISMPC
  if (S_ISMPC (bits))
    return 'm';
#endif
#ifdef S_ISNWK
  if (S_ISNWK (bits))
    return 'n';
#endif
#ifdef S_ISDOOR
  if (S_ISDOOR (bits))
    return 'D';
#endif
#ifdef S_ISCTG
  if (S_ISCTG (bits))
    return 'C';
#endif

  /* The following two tests are for Cray DMF (Data Migration
     Facility), which is a HSM file system.  A migrated file has a
     `st_dm_mode' that is different from the normal `st_mode', so any
     tests for migrated files should use the former.  */

#ifdef S_ISOFD
  if (S_ISOFD (bits))
    /* off line, with data  */
    return 'M';
#endif
#ifdef S_ISOFL
  /* off line, with no data  */
  if (S_ISOFL (bits))
    return 'M';
#endif
  return '?';
}

void vfs_mode_string (mode_t mode, char *str)
{
  str[0] = ftypelet (mode);
  str[1] = mode & S_IRUSR ? 'r' : '-';
  str[2] = mode & S_IWUSR ? 'w' : '-';
  str[3] = mode & S_IXUSR ? 'x' : '-';
  str[4] = mode & S_IRGRP ? 'r' : '-';
  str[5] = mode & S_IWGRP ? 'w' : '-';
  str[6] = mode & S_IXGRP ? 'x' : '-';
  str[7] = mode & S_IROTH ? 'r' : '-';
  str[8] = mode & S_IWOTH ? 'w' : '-';
  str[9] = mode & S_IXOTH ? 'x' : '-';
  setst (mode, str);
}




static char * get_full_path(char * buffer, ssize_t size, const char * cwd, const char * fname)
{
    int len = 0, isdir = 0;
    char real[MAX_PATH_BUFFER];
    char * str, * saveptr, * token;
    char * grid[256] = {NULL};
    int i,j;

    if(!buffer || !cwd || !fname)
        return NULL;


    if(fname[0] == '/') {
        len = strlen(fname);
        strncpy(real, fname, sizeof(real) - 1);
    } else {
        len = strlen(cwd);
        strncpy(real, cwd,  sizeof(real) - 1);
        if(real[len - 1] != '/')
            real[len ++ ] = '/';
        strncpy(real + len, fname, sizeof(real) - 1 - len);
    }

    real[MAX_PATH_BUFFER - 1] = 0; /*may hold .. and . */

    SDBG("get_full_path raw = %s\n", real);

    len = strlen(real);

    if(real[len - 1] == '/')
        isdir = 1;

    for (i = 0, j = 0, str = real; j < 255; i++, str = NULL) {
        token = strtok_r(str, "/", &saveptr);
        if (token == NULL)
            break;

        if(!strcmp(token, "."))
            continue;

        if(!strcmp(token, "..")) {
            if(j > 0) j --;
            continue;
        }

        grid[j] = token; j++;
    }

    grid[j] = NULL;


    memset(buffer, 0, size);
    for(i = 0 , len = 0; i < j && len < size - 1 ; i++) {
        len += snprintf(buffer + len, size - len, "/%s", grid[i]);
        SDBG("token: %s\n", grid[i]);
    }

    if(isdir) {
        buffer[len] = '/';
    }

    if(!buffer[0]) {
        buffer[0] = '/';
        buffer[1] = 0;
    }

    SDBG("get_full_path %s + %s => %s\n", cwd, fname, buffer);

    return buffer;
}

vfs_t *vfs_openfs( void )
{
    vfs_t * ret = malloc(sizeof(vfs_t));
    if(NULL != ret) {
        ret->cwd = strdup("/");
        ret->list_dir = NULL;
    }
    return ret;
}


void vfs_closefs( vfs_t * fs )
{
    if(fs != NULL) {
        if(fs->cwd != NULL) {
            free(fs->cwd);
            fs->cwd = NULL;
        }
        if(fs->list_dir != NULL) {
            free(fs->list_dir);
            fs->list_dir = NULL;
        }
        free(fs);
    }
}

vfs_file_t *vfs_open( vfs_t * fs, const char *fname, const char *mode)
{
    char buf[MAX_PATH_BUFFER];
    char * path;

    path = get_full_path(buf, sizeof(buf), fs->cwd, fname);

    if(NULL != path)
        return (vfs_file_t *)fopen( path, mode );
    else
        return NULL;
}


size_t vfs_read( void *buf,int what, int BufferSize, vfs_file_t *fp )
{
    return fread( buf, what, BufferSize, (FILE*)fp);
}


size_t vfs_write(  void *buf,int what, int BufferSize, vfs_file_t *fp  )
{
    return fwrite( buf, what, BufferSize, (FILE*)fp);
}


int vfs_eof( vfs_file_t *fp )
{
    return feof( (FILE*)fp );
}


int vfs_close( vfs_file_t *fp  )
{
    if( NULL != fp )
    {
        fclose( (FILE*)fp );
    }
    return 0;
}


int vfs_stat( vfs_t * fs, const char *fname, vfs_stat_t *st )
{
    int ret = -1;
    char buf[MAX_PATH_BUFFER];
    char * path;

    SDBG("vfs_stat %s %s %s\n", fs->cwd, fs->list_dir, fname);

    if(NULL != fs->list_dir && fs->list_dir[0]) {
        path = get_full_path(buf, sizeof(buf), fs->list_dir, fname);
    } else {
        path = get_full_path(buf, sizeof(buf), fs->cwd, fname);
    }

    if(NULL != path) {
        ret = stat(path, st);
    }
    return ret;
}

char *vfs_getcwd( vfs_t * fs, void *x, int y )
{
    LWIP_UNUSED_ARG(x);
    LWIP_UNUSED_ARG(y);
    return strdup(fs->cwd);
}


vfs_dir_t    *vfs_opendir( vfs_t * fs, const char *dir )
{
    char buf[MAX_PATH_BUFFER];
    char * path;
    vfs_dir_t    * ret = NULL;

    path = get_full_path(buf, sizeof(buf), fs->cwd, dir);
    if(NULL != path) {
        ret = (vfs_dir_t *)opendir(path);
        if(NULL != ret) {
            if(fs->list_dir) {
                free(fs->list_dir);
                fs->list_dir = NULL;
            }
            fs->list_dir = strdup(path);
        }
        return ret;
    } 

    return NULL;
}


vfs_dirent_t *vfs_readdir( vfs_dir_t *fd )
{
    return readdir(fd);
}


int vfs_closedir( vfs_dir_t *fd )
{
    return closedir(fd);
}


int vfs_mkdir( vfs_t * fs, const char *arg, mode_t mode )
{
    char buf[MAX_PATH_BUFFER];
    char * path;

    path = get_full_path(buf, sizeof(buf), fs->cwd, arg);
    if(NULL != path) {
        return mkdir(path, mode);
    }
    
    return -1;
}


int vfs_rmdir( vfs_t * fs, const char *arg )
{
    char buf[MAX_PATH_BUFFER];
    char * path;

    path = get_full_path(buf, sizeof(buf), fs->cwd, arg);
    if(NULL != path) {
        return rmdir(path);
    }

    return -1;
}


int vfs_rename( vfs_t * fs, char *oldname, const char *newname )
{
    char buf_old[MAX_PATH_BUFFER], buf_new[MAX_PATH_BUFFER];
    char * path_old, * path_new;

    path_old = get_full_path(buf_old, sizeof(buf_old), fs->cwd, oldname);
    path_new = get_full_path(buf_new, sizeof(buf_new), fs->cwd, newname);

    if(NULL != path_old && NULL != path_new) {
        return rename( path_old, path_new );
    }

    return -1;
}


int vfs_remove( vfs_t * fs, const char *arg )
{
    char buf[MAX_PATH_BUFFER];
    char * path;

    path = get_full_path(buf, sizeof(buf), fs->cwd, arg);
    if(NULL != path) {
        return remove(path);
    }
    return -1;
}


int vfs_chdir( vfs_t * fs, const char *arg )
{
    char buf[MAX_PATH_BUFFER];
    char * path;

    path = get_full_path(buf, sizeof(buf), fs->cwd, arg);
    if(NULL != path) {
        if(access(path, R_OK|X_OK) == 0) {
            if(fs->cwd) {
                free(fs->cwd);
            }

            fs->cwd = strdup(path);
            return 0;
        }
    }
    return -1;
}

