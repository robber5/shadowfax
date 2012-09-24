#include <stdlib.h>
#include <string.h>
#include "fifo.h"


/*
 * Alloc buffer, init FIFO etc...
 */
int sfifo_init(sfifo_t *f, int size)
{
	memset(f, 0, sizeof(sfifo_t));

	if(size > SFIFO_MAX_BUFFER_SIZE)
		return -1;

	/*
	 * Set sufficient power-of-2 size.
	 *
	 * No, there's no bug. If you need
	 * room for N bytes, the buffer must
	 * be at least N+1 bytes. (The fifo
	 * can't tell 'empty' from 'full'
	 * without unsafe index manipulations
	 * otherwise.)
	 */
	f->size = 1;
	for(; f->size <= size; f->size <<= 1)
		;

	/* Get buffer */
	if( 0 == (f->buffer = (void *)malloc(f->size)) )
		return -1;

	return 0;
}

/*
 * Dealloc buffer etc...
 */
void sfifo_close(sfifo_t *f)
{
	if(f->buffer)
		free(f->buffer);
        f->buffer = NULL;
}

/*
 * Empty FIFO buffer
 */

void sfifo_flush(sfifo_t *f)
{
	f->readpos = 0;
	f->writepos = 0;
}

/*
 * Write bytes to a FIFO
 * Return number of bytes written, or an error code
 */
int sfifo_write(sfifo_t *f, const void *_buf, int len)
{
	int total;
	int i;
	const char *buf = (const char *)_buf;

	if(!f->buffer)
		return -1;	/* No buffer! */

	/* total = len = min(space, len) */
	total = sfifo_space(f);
	/* dbg_printf("sfifo_space() = %d\n",total); */
	if(len > total)
		len = total;
	else
		total = len;

	i = f->writepos;
	if(i + len > f->size)
	{
		memcpy(f->buffer + i, buf, f->size - i);
		buf += f->size - i;
		len -= f->size - i;
		i = 0;
	}
	memcpy(f->buffer + i, buf, len);
	f->writepos = i + len;

	return total;
}

/*
 * Read bytes from a FIFO
 * Return number of bytes read, or an error code
 */

int sfifo_read(sfifo_t *f, void *_buf, int len)
{
	int total;
	int i;
	char *buf = (char *)_buf;

	if(!f->buffer)
		return -1;

	/*total = len = used > len ? len : used;*/

	total = sfifo_used(f);

	if(len > total)
		len = total;
	else
		total = len;

	i = f->readpos;
	if(i + len > f->size)
	{
		memcpy(buf, f->buffer + i, f->size - i);
		buf += f->size - i;
		len -= f->size - i;
		i = 0;
	}
	memcpy(buf, f->buffer + i, len);
	f->readpos = i + len;

	return total;
}

int sfifo_try_read(sfifo_t *f, void *_buf, int len)
{
	int total;
	int i;
	char *buf = (char *)_buf;

	if(!f->buffer)
		return -1;

	/*total = len = used > len ? len : used;*/

	total = sfifo_used(f);

	if(len > total)
		len = total;
	else
		total = len;

	i = f->readpos;
	if(i + len > f->size)
	{
		memcpy(buf, f->buffer + i, f->size - i);
		buf += f->size - i;
		len -= f->size - i;
		i = 0;
	}
	memcpy(buf, f->buffer + i, len);
	return total;
}

int sfifo_read_ack(sfifo_t *f, int len)
{
    int i;

	if(!f->buffer)
		return -1;

	i = f->readpos;
	if(i + len > f->size)
	{
		len -= f->size - i;
		i = 0;
	}
    f->readpos = i + len;

	return 0;
}

