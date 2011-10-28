/*
 *  V4L2 video capture example
 *
 *  This program can be used and distributed without restrictions.
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <getopt.h>             /* getopt_long() */

#include <fcntl.h>              /* low-level i/o */
#include <unistd.h>
#include <errno.h>
#include <malloc.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <stdint.h>

#include <asm/types.h>          /* for videodev2.h */

#include <linux/videodev2.h>

#ifdef HTTPD
#	include <microhttpd.h>
	const char http_multipart_header_template[] =
			"--on-ipcam\n"
			"Content-Type: image/jpeg\n"
			"Content-Length: xxxxxx\n\n";
#endif

#ifdef LOCKS
#	include <pthread.h>
#endif

#ifdef JPEG_SIGN
#	include "jpegsign.h"
	static RSA* rsa_key;
	static char jpeg_sign = 0;
#endif

#ifdef JPEG_DECODE
#	include "jpegdecode.h"
	static char jpeg_decode = 0;
#endif

#ifdef PROFILING
#	include "profiling.h"
	int g_profileDepth;
#endif

#include "v4l2_control.h"

#define CLEAR(x) memset (&(x), 0, sizeof (x))


typedef enum {
	IO_METHOD_READ, IO_METHOD_MMAP, IO_METHOD_USERPTR,
} io_method;

static char * dev_name = "/dev/video0";
static io_method io = IO_METHOD_MMAP;
static int mmap_flags = MAP_SHARED;
int fd = -1;
static unsigned int i = 0;
static unsigned int count = 100;
static unsigned int width = 640;
static unsigned int height = 480;
static int frame_counter = 0;
static char verbose = 0;
static char restart_cam = 0;

struct buffer_t {
	struct v4l2_buffer buf;
	void* start;
	size_t length;
	int frame_id;
	int refcount;
#ifdef LOCKS
	pthread_mutex_t mutex;
#endif
#ifdef HTTPD
	char http_multipart_header[sizeof(http_multipart_header_template)-1];
#endif
	char queued;
};

struct buffer_t ringbuffer[BUFFER_COUNT];

static void errno_exit(const char * s)
{
	fprintf(stderr, "%s error %d, %s\n", s, errno, strerror(errno));
	exit(EXIT_FAILURE);
}

static void init_buffers()
{
	for(int i=0; i<BUFFER_COUNT; i++) {
		ringbuffer[i].refcount = 0;
		ringbuffer[i].queued = 0;

#ifdef HTTPD
		memcpy(ringbuffer[i].http_multipart_header,
		       http_multipart_header_template,
		       sizeof(http_multipart_header_template)-1);
#endif
#ifdef LOCKS
		if(pthread_mutex_init(&ringbuffer[i].mutex, 0))
			errno_exit("Cannot create mutex");
#endif
	}
}

static void destroy_buffers()
{
	for(int i=0; i<BUFFER_COUNT; i++) {
		// wait for refcount == 0
		while(ringbuffer[i].refcount > 0) usleep(1000);
#ifdef LOCKS
		pthread_mutex_destroy(&ringbuffer[i].mutex);
#endif
	}
}

static int xioctl(int fd, int request, void * arg)
{
	int r;

	do
		r = ioctl(fd, request, arg);
	while (-1 == r && EINTR == errno);

	return r;
}

#ifdef BUFFER_DEBUG
static void dump_ringbuffer(const char* tag)
{
	printf("RINGBUFFER %s:\n", tag);
	for(int i=0; i<BUFFER_COUNT; i++) {
		printf("index:%d  frame_id:%d  refcount:%d  queued:%d  @0x%08x length:%d\n", i,
				ringbuffer[i].frame_id,
				ringbuffer[i].refcount,
				ringbuffer[i].queued,
				(unsigned int)ringbuffer[i].start,
				ringbuffer[i].length
		);
	}
}
#endif

static int read_frame(void)
{
	struct v4l2_buffer buf_v4l;
	struct buffer_t* buf = NULL;

	// For mmap() and userp we don't know yet which entry in ringbuffer will
	// be used. This index is stored in the v4l2_buffer struct and will be
	// known only after the ioctl() call to dequeue it.
	// For read() we can choose any queued buffer.

	switch (io) {
	case IO_METHOD_READ:
		;
		// find a queued buffer
		int frame_idx = -1;
		for(int i=0; i<BUFFER_COUNT && frame_idx == -1; i++) {
			if(ringbuffer[i].queued)
				frame_idx = i;
		}
		if(frame_idx == -1) {
			printf("Warning: no queued buffer available\n");
			return 0;
		}

		buf = &ringbuffer[frame_idx];

		// read frame into the buffer
		int buffer_size = read(fd, buf->start, buf->length);
		if (-1 == buffer_size) {
			switch (errno) {
			case EAGAIN:
				return 0;

			case EIO:
				/* Could ignore EIO, see spec. */

				/* fall through */

			default:
				errno_exit("read");
			}
		}

		// Store the length of the data in the v4l buffer. It is unused for
		// IO_METHOD_READ, but other code needs to know the length.
		buf->buf.bytesused = buffer_size;

		break;

	case IO_METHOD_MMAP:
		CLEAR(buf_v4l);

		buf_v4l.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
		buf_v4l.memory = V4L2_MEMORY_MMAP;

		if (-1 == xioctl(fd, VIDIOC_DQBUF, &buf_v4l)) {
			switch (errno) {
			case EAGAIN:
				return 0;

			case EIO:
				/* Could ignore EIO, see spec. */

				/* fall through */

			default:
				errno_exit("VIDIOC_DQBUF");
			}
		}

		// Copy the V4L buffer (small, the frame data is only a pointer)
		buf = &ringbuffer[buf_v4l.index];
		memcpy(&buf->buf, &buf_v4l, sizeof(buf_v4l));
		break;

	case IO_METHOD_USERPTR:
		CLEAR(buf_v4l);

		buf_v4l.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
		buf_v4l.memory = V4L2_MEMORY_USERPTR;

		if (-1 == xioctl(fd, VIDIOC_DQBUF, &buf_v4l)) {
			switch (errno) {
			case EAGAIN:
				return 0;

			case EIO:
				/* Could ignore EIO, see spec. */

				/* fall through */

			default:
				errno_exit("VIDIOC_DQBUF");
			}
		}

		// Copy the V4L buffer (small, the frame data is only a pointer)
		buf = &ringbuffer[buf_v4l.index];
		memcpy(&buf->buf, &buf_v4l, sizeof(buf_v4l));
		break;
	}

	buf->frame_id = frame_counter++;

#ifdef HTTPD
	char size[7];
	sprintf(size, "%6d", buf->buf.bytesused < 1000000 ? buf->buf.bytesused
	                                                  : 999999);
	memcpy(&buf->http_multipart_header[sizeof(buf->http_multipart_header) - 8],
	       size, 6);
#endif

#ifdef JPEG_SIGN
	if(jpeg_sign) {
		printf("Signing JPEG frame...\n");
		sign_data(buf->start, buf->buf.bytesused, rsa_key);
	}
#endif

#ifdef JPEG_DECODE
	if(jpeg_decode) {
		PROFILE_BEGIN(jpeg_decode)

		printf("Decoding subsampled JPEG frame...\n");

		// Decode the JPEG into a subsampled grayscale image
		unsigned char* img;
		int width, height, comps;
		decode_jpeg(buf->start, buf->buf.bytesused, 8,
					&img, &width, &height, &comps);

		printf("Decoded a %d x %d x %d image\n", width, height, comps);

		// Write out decoded image to a PGM file for inspection
		if(img && jpeg_decode > 1)
			write_pgm("/tmp/test.pgm", img, width, height);
		free(img);

		PROFILE_END(jpeg_decode)
		/* 120 ms for a 640x480 image on a NUC745 */
	}
#endif

	// At last, release the buffer into the wild...
	buf->queued = 0;

	return 1;
}

static void mainloop(void)
{
	while (count-- > 0 && !restart_cam) {
		for (;;) {
			fd_set fds;
			struct timeval tv;
			int r;

			FD_ZERO(&fds);
			FD_SET(fd, &fds);

			/* Timeout. */
			tv.tv_sec = 10;
			tv.tv_usec = 0;

			r = select(fd + 1, &fds, NULL, NULL, &tv);

			if (-1 == r) {
				if (EINTR == errno
				)
					continue;

				errno_exit("select");
			}

			if (0 == r) {
				fprintf(stderr, "select timeout\n");
				exit(EXIT_FAILURE);
			}

			if (read_frame())
				break;

			/* EAGAIN - continue select loop. */
		}

		int queued_buffers = 0;
		for(int i=0; i<BUFFER_COUNT; i++)
			if(ringbuffer[i].queued)
				queued_buffers++;

#ifdef BUFFER_DEBUG
		dump_ringbuffer("after a frame has been read");
#endif

		while(queued_buffers < MIN_QUEUED) {
			// Locate the oldest unqueued buffer that has refcount == 0.
			int frame_id = INT32_MAX, frame_idx = -1;
			for(int i=0; i<BUFFER_COUNT; i++) {
				if(!ringbuffer[i].queued &&
				   ringbuffer[i].refcount == 0 &&
				   frame_id > ringbuffer[i].frame_id)
				{
					frame_id = ringbuffer[i].frame_id;
					frame_idx = i;
				}
			}

			if(frame_idx == -1) {
				// No buffer ready to be queued
				break;
			}

#ifdef LOCKS
			pthread_mutex_lock(&ringbuffer[frame_idx].mutex);
#endif

			// Verify that refcount is still zero (i.e., no clients reading)
			if(ringbuffer[frame_idx].refcount == 0) {
#ifdef BUFFER_DEBUG
				printf("Enqueue buffer %d\n", frame_idx);
#endif

				if(io != IO_METHOD_READ) {
					if (-1 == xioctl(fd, VIDIOC_QBUF, &ringbuffer[frame_idx].buf))
						errno_exit("VIDIOC_QBUF");
				}

				ringbuffer[frame_idx].queued = 1;
				queued_buffers++;
			}

#ifdef LOCKS
			pthread_mutex_unlock(&ringbuffer[frame_idx].mutex);
#endif
		}
	}
}

static void stop_capturing(void) {
	enum v4l2_buf_type type;

	switch (io) {
	case IO_METHOD_READ:
		/* Nothing to do. */
		break;

	case IO_METHOD_MMAP:
	case IO_METHOD_USERPTR:
		type = V4L2_BUF_TYPE_VIDEO_CAPTURE;

		if (-1 == xioctl(fd, VIDIOC_STREAMOFF, &type))
			errno_exit("VIDIOC_STREAMOFF");

		break;
	}
}

static void start_capturing(void)
{
	unsigned int i;
	enum v4l2_buf_type type;

	switch (io) {
	case IO_METHOD_READ:
		/* Nothing to do. */
		break;

	case IO_METHOD_MMAP:
		for (i = 0; i < BUFFER_COUNT; ++i) {
			struct v4l2_buffer buf_v4l;

			CLEAR(buf_v4l);

			buf_v4l.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
			buf_v4l.memory = V4L2_MEMORY_MMAP;
			buf_v4l.index = i;

			if (-1 == xioctl(fd, VIDIOC_QBUF, &buf_v4l))
				errno_exit("VIDIOC_QBUF");

			ringbuffer[i].queued = 1;
		}

		type = V4L2_BUF_TYPE_VIDEO_CAPTURE;

		if (-1 == xioctl(fd, VIDIOC_STREAMON, &type))
			errno_exit("VIDIOC_STREAMON");

		break;

	case IO_METHOD_USERPTR:
		for (i = 0; i < BUFFER_COUNT; ++i) {
			struct v4l2_buffer buf_v4l;

			CLEAR(buf_v4l);

			buf_v4l.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
			buf_v4l.memory = V4L2_MEMORY_USERPTR;
			buf_v4l.index = i;
			buf_v4l.m.userptr = (unsigned long)ringbuffer[i].start;
			buf_v4l.length = ringbuffer[i].length;

			if (-1 == xioctl(fd, VIDIOC_QBUF, &buf_v4l))
				errno_exit("VIDIOC_QBUF");

			ringbuffer[i].queued = 1;
		}

		type = V4L2_BUF_TYPE_VIDEO_CAPTURE;

		if (-1 == xioctl(fd, VIDIOC_STREAMON, &type))
			errno_exit("VIDIOC_STREAMON");

		break;
	}
}

static void init_read(unsigned int buffer_size)
{
	for(int i=0; i<BUFFER_COUNT; i++) {
		printf("Allocating buffer with size %d for read()\n", buffer_size);
		ringbuffer[i].length = buffer_size;
		ringbuffer[i].start = malloc(buffer_size);
		ringbuffer[i].queued = 1;
		if (!ringbuffer[i].start) {
			fprintf(stderr, "Out of memory\n");
			exit(EXIT_FAILURE);
		}
	}
}

static void init_mmap(char free_buffers)
{
	printf("init_mmap, free_buffers = %d\n", free_buffers);
	struct v4l2_requestbuffers req;

	CLEAR(req);

	int request_count = free_buffers ? 0 : BUFFER_COUNT;
	req.count = request_count;
	req.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
	req.memory = V4L2_MEMORY_MMAP;

	if (-1 == xioctl(fd, VIDIOC_REQBUFS, &req)) {
		if (EINVAL == errno) {
			fprintf(stderr, "%s does not support memory mapping\n", dev_name);
			exit(EXIT_FAILURE);
		} else {
			errno_exit("VIDIOC_REQBUFS");
		}
	}

	if (req.count != request_count) {
		fprintf(stderr, "Insufficient buffer memory on %s\n", dev_name);
		exit(EXIT_FAILURE);
	}

	for (i = 0; i < req.count; ++i) {
		struct buffer_t* buf = &ringbuffer[i];
		struct v4l2_buffer* buf_v4l = &buf->buf;

		CLEAR(*buf_v4l);

		buf_v4l->type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
		buf_v4l->memory = V4L2_MEMORY_MMAP;
		buf_v4l->index = i;

		if (-1 == xioctl(fd, VIDIOC_QUERYBUF, buf_v4l))
			errno_exit("VIDIOC_QUERYBUF");

		/*printf("Calling mmap(), length = %d, offset = %d\n",
				buf_v4l->length, buf_v4l->m.offset);*/
		buf->length = buf_v4l->length;

		buf->start = mmap(NULL /* start anywhere */,
		                  buf->length,
		                  PROT_READ | PROT_WRITE /* required */,
		                  mmap_flags /* recommended */, fd, buf_v4l->m.offset);

		if (MAP_FAILED == buf->start)
			errno_exit("mmap");
	}
}

static void init_userp(unsigned int buffer_size)
{
	struct v4l2_requestbuffers req;
	unsigned int page_size;

	page_size = getpagesize();
	buffer_size = (buffer_size + page_size - 1) & ~(page_size - 1);

	CLEAR(req);

	req.count = BUFFER_COUNT;
	req.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
	req.memory = V4L2_MEMORY_USERPTR;

	if (-1 == xioctl(fd, VIDIOC_REQBUFS, &req)) {
		if (EINVAL == errno) {
			fprintf(stderr, "%s does not support user pointer i/o\n", dev_name);
			exit(EXIT_FAILURE);
		} else {
			errno_exit("VIDIOC_REQBUFS");
		}
	}

	for (i = 0; i < BUFFER_COUNT; ++i) {
		printf("Allocating buffer with size %d for userp\n", buffer_size);

		struct buffer_t* buf = &ringbuffer[i];

		buf->length = buffer_size;
		buf->start = memalign(/* boundary */page_size, buffer_size);

		if (!buf->start) {
			fprintf(stderr, "Out of memory\n");
			exit(EXIT_FAILURE);
		}
	}
}

static void init_device(void)
{
	struct v4l2_capability cap;
	struct v4l2_cropcap cropcap;
	struct v4l2_crop crop;
	struct v4l2_format fmt;
	unsigned int min;

	if (-1 == xioctl(fd, VIDIOC_QUERYCAP, &cap)) {
		if (EINVAL == errno) {
			fprintf(stderr, "%s is no V4L2 device\n", dev_name);
			exit(EXIT_FAILURE);
		} else {
			errno_exit("VIDIOC_QUERYCAP");
		}
	}

	if (!(cap.capabilities & V4L2_CAP_VIDEO_CAPTURE)) {
		fprintf(stderr, "%s is no video capture device\n", dev_name);
		exit(EXIT_FAILURE);
	}

	switch (io) {
	case IO_METHOD_READ:
		if (!(cap.capabilities & V4L2_CAP_READWRITE)) {
			fprintf(stderr, "%s does not support read i/o\n", dev_name);
			exit(EXIT_FAILURE);
		}

		break;

	case IO_METHOD_MMAP:
	case IO_METHOD_USERPTR:
		if (!(cap.capabilities & V4L2_CAP_STREAMING)) {
			fprintf(stderr, "%s does not support streaming i/o\n", dev_name);
			exit(EXIT_FAILURE);
		}

		break;
	}

	/* Select video input, video standard and tune here. */

	CLEAR(cropcap);

	cropcap.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;

	if (0 == xioctl(fd, VIDIOC_CROPCAP, &cropcap)) {
		crop.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
		crop.c = cropcap.defrect; /* reset to default */

		if (-1 == xioctl(fd, VIDIOC_S_CROP, &crop)) {
			switch (errno) {
			case EINVAL:
				/* Cropping not supported. */
				break;
			default:
				/* Errors ignored. */
				break;
			}
		}
	} else {
		/* Errors ignored. */
	}

	CLEAR(fmt);

	printf("Resolution is %d x %d\n", width, height);

	fmt.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
	fmt.fmt.pix.width = width;
	fmt.fmt.pix.height = height;
	fmt.fmt.pix.pixelformat = V4L2_PIX_FMT_JPEG; //V4L2_PIX_FMT_YUV420;
	fmt.fmt.pix.field = V4L2_FIELD_NONE;

	if (-1 == xioctl(fd, VIDIOC_S_FMT, &fmt))
		errno_exit("VIDIOC_S_FMT");

	/* Note VIDIOC_S_FMT may change width and height. */

	/* Buggy driver paranoia. */
	/* Let's believe the driver to choose the right size for JPEG frames */
	min = fmt.fmt.pix.width * 2;
	if (fmt.fmt.pix.bytesperline < min)
		fmt.fmt.pix.bytesperline = min;
	min = fmt.fmt.pix.bytesperline * fmt.fmt.pix.height;
	if (fmt.fmt.pix.sizeimage < min)
		fmt.fmt.pix.sizeimage = min;

	switch (io) {
	case IO_METHOD_READ:
		init_read(fmt.fmt.pix.sizeimage);
		break;

	case IO_METHOD_MMAP:
		init_mmap(0);
		break;

	case IO_METHOD_USERPTR:
		init_userp(fmt.fmt.pix.sizeimage);
		break;
	}
}

static void uninit_device(void)
{
	unsigned int i;

	switch (io) {
	case IO_METHOD_READ:
	case IO_METHOD_USERPTR:
		for(int i=0; i<BUFFER_COUNT; i++) {
			// wait for refcount == 0
			while(ringbuffer[i].refcount > 0) usleep(1000);

			free(ringbuffer[i].start);
		}
		break;

	case IO_METHOD_MMAP:
		for (i = 0; i < BUFFER_COUNT; ++i) {
			// wait for refcount == 0
			while(ringbuffer[i].refcount > 0) usleep(1000);
			if (-1 == munmap(ringbuffer[i].start,
			                 ringbuffer[i].length))
				errno_exit("munmap");
		}
		// call init_mmap() to request 0 buffers (i.e., free all buffers)
		init_mmap(1);

		break;
	}
}

static void close_device(void)
{
	if (-1 == close(fd))
		errno_exit("close");

	fd = -1;
}

static void open_device(void)
{
	struct stat st;

	if (-1 == stat(dev_name, &st)) {
		fprintf(stderr, "Cannot identify '%s': %d, %s\n", dev_name, errno,
				strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (!S_ISCHR (st.st_mode)) {
		fprintf(stderr, "%s is no device\n", dev_name);
		exit(EXIT_FAILURE);
	}

	fd = open(dev_name, O_RDWR /* required */| O_NONBLOCK, 0);

	if (-1 == fd) {
		fprintf(stderr, "Cannot open '%s': %d, %s\n", dev_name, errno,
				strerror(errno));
		exit(EXIT_FAILURE);
	}
}

/*******************************************************************************
 *** HTTP SERVER
 ******************************************************************************/

struct client_state {
	int frame_id;
	int frame_idx;
	int frame_offset;
	char snapshot;
};

static ssize_t http_frame_reader(void *cls, uint64_t pos, char *send_buf, size_t max)
{
	struct client_state *s = (struct client_state *)cls;
#ifdef BUFFER_DEBUG
	printf("http_frame_reader, frame_id:%d frame_idx:%d frame_offset:%d\n",
	       s->frame_id, s->frame_idx, s->frame_offset);
	dump_ringbuffer("in file_reader");
#endif
	int hdr_sz = sizeof(http_multipart_header_template)-1;

	// Return end-of-stream when snapshot has been sent completely
	if(s->snapshot == 2)
		return MHD_CONTENT_READER_END_OF_STREAM;

	// Initialize if this is the first call during a connection or
	// the previous frame has been sent and a new one is needed.
	if(s->frame_offset == -1) {
		// Locate the latest frame that has not yet been sent
		// and send it to the client
		int frame_id = -1, frame_idx = -1;
		for(int i=0; i<BUFFER_COUNT; i++) {
			/*printf("q:%d s->fid:%d fid:%d < rb.fid:%d\n",
					ringbuffer[i].queued,
					s->frame_id, frame_id, ringbuffer[i].frame_id);*/
			// this will overflow after ~2 years at 30 fps...
			if(!ringbuffer[i].queued &&
			   s->frame_id < ringbuffer[i].frame_id &&
				  frame_id < ringbuffer[i].frame_id)
			{
				frame_id = ringbuffer[i].frame_id;
				frame_idx = i;
			}
		}
#ifdef BUFFER_DEBUG
		printf("block is %d [%d]\n", frame_id, frame_idx);
#endif

		if(frame_id == -1) {  // no data is available
			usleep(20*1000);
			return 0;         // ok for MHD_USE_THREAD_PER_CONNECTION
		}

		if(frame_id > s->frame_id + 1)
			printf("Frame dropped (jumping from %d to %d) for client 0x%08x\n",
			       s->frame_id, frame_id, (unsigned int)s);

		s->frame_id = frame_id;
		s->frame_idx = frame_idx;

		pthread_mutex_lock(&ringbuffer[s->frame_idx].mutex);
		// might have been queued since above (probably rare)
		if(ringbuffer[i].queued) {
			pthread_mutex_unlock(&ringbuffer[s->frame_idx].mutex);
			usleep(1000);
			return 0;
		}

		ringbuffer[s->frame_idx].refcount++;
		pthread_mutex_unlock(&ringbuffer[s->frame_idx].mutex);

		if(!s->snapshot)
			s->frame_offset = 0;
		else
			s->frame_offset = hdr_sz;  // skip multipart header
	}

	struct buffer_t* buf = &ringbuffer[s->frame_idx];

	int len;
	if(s->frame_offset < hdr_sz) {
		//printf("sending header %d\n", hdr_sz);
		// need to send the HTTP multipart header
		len = hdr_sz - s->frame_offset;
		if(len > max) len = max;

		memcpy(send_buf, buf->http_multipart_header + s->frame_offset, len);
	} else {
		//printf("sending payload %d\n", buf->buf.bytesused);
		// need to send the payload
		int data_offset = s->frame_offset - hdr_sz;

		len = buf->buf.bytesused - data_offset;
		if(len > max) len = max;

		memcpy(send_buf, (char*)buf->start + data_offset, len);
	}

	s->frame_offset += len;
	//printf("Served %d bytes to client 0x%08x\n", len, (unsigned int)s);
	//printf("Client is at %d of %d + %d = %d bytes\n", s->frame_offset, hdr_sz,
	//       buf->buf.bytesused, hdr_sz + buf->buf.bytesused);

	if(s->frame_offset >= hdr_sz + buf->buf.bytesused) {
		// Frame complete
		//printf("Frame %d [%d] is complete.\n", buf->frame_id, s->frame_idx);
		pthread_mutex_lock(&buf->mutex);
		buf->refcount--;
		pthread_mutex_unlock(&buf->mutex);

		// Schedule frame selection for the next callback
		s->frame_offset = -1;

		if(s->snapshot)
			s->snapshot = 2;           // => return end-of-stream next time
	}

	return len;
}

static void http_free_callback(void *cls)
{
	struct client_state *s = (struct client_state *)cls;
	printf("Freeing resources for client\n");

	if(s->frame_offset != -1) {
		printf("Decreased refcount for the buffer-in-progress\n");

		struct buffer_t* buf = &ringbuffer[s->frame_idx];
		pthread_mutex_lock(&buf->mutex);
		buf->refcount--;
		pthread_mutex_unlock(&buf->mutex);
	}
	free(s);
}


/**
 * Handler used to generate a 404 reply.
 *
 * @param cls a 'const char *' with the HTML webpage to return
 * @param mime mime type to use
 * @param session session handle
 * @param connection connection to use
 */
static const char NOT_FOUND_ERROR[] =
		"<html><head><title>Page not found</title></head>"
		"<body><h1>404 - Page Not Found</h1></body></html>";

static int mk_response_404(struct MHD_Connection *connection)
{
	int ret;
	struct MHD_Response *response;

	response = MHD_create_response_from_buffer(strlen(NOT_FOUND_ERROR),
			   (void*)NOT_FOUND_ERROR, MHD_RESPMEM_PERSISTENT);

	ret = MHD_queue_response(connection, MHD_HTTP_NOT_FOUND, response);
	MHD_destroy_response(response);
	return ret;
}

static int mk_response_text(struct MHD_Connection *connection, const char* text)
{
	int ret;
	struct MHD_Response *response;

	response = MHD_create_response_from_buffer(strlen(text),
			   (char*)text, MHD_RESPMEM_PERSISTENT);

	ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
	MHD_destroy_response(response);
	return ret;
}

static int process_get_param_resolution(struct MHD_Connection* connection, int* ret)
{
	const char* q = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "resolution");
	if(q) {
		int w, h, resolution = atoi(q);
		switch(resolution) {
		case 8 : w = 320; h = 240; break;
		case 32: w = 640; h = 480; break;
		default:
			*ret = mk_response_text(connection, "Invalid resolution, valid is: 8 (320x240), 32 (640x480)");
			return 1;
		}
		if(w != width) {
			width = w;
			height = h;
			restart_cam = 1;     // triggers mainloop exit & camera restart
		}
	}
	return 0;
}

int http_request_handler(void *cls, struct MHD_Connection *connection,
		const char *url, const char *method, const char *version,
		const char *upload_data, size_t *upload_data_size, void **ptr)
{
	static int aptr;
	struct MHD_Response *response;
	int ret;

	if (0 != strcmp(method, "GET"))
		return MHD_NO; /* unexpected method */
	if (&aptr != *ptr) {
		/* do never respond on first call */
		*ptr = &aptr;
		return MHD_YES;
	}
	*ptr = NULL; /* reset when done */

	if(!strcmp(url, "/videostream.cgi")) {
		if(process_get_param_resolution(connection, &ret))
			return ret;

		struct client_state *s = (struct client_state *)malloc(sizeof(struct client_state));
		s->frame_offset = -1;    // means: need to select a buffer
		s->frame_id = -1;        // any frame will do
		s->snapshot = 0;

		response = MHD_create_response_from_callback (
				-1, 32 * 1024,     /* 32k page size */
				&http_frame_reader, s, &http_free_callback);

		MHD_add_response_header(response, "Content-Type",
								"multipart/x-mixed-replace;boundary=on-ipcam");

		ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
		MHD_destroy_response(response);
		return ret;

	} else if(!strcmp(url, "/snapshot.cgi")) {
		// TODO on resolution change, don't deliver old frames
		if(process_get_param_resolution(connection, &ret))
			return ret;

		struct client_state *s = (struct client_state *)malloc(sizeof(struct client_state));
		s->frame_offset = -1;    // means: need to select a buffer
		s->frame_id = -1;        // any frame will do
		s->snapshot = 1;

		response = MHD_create_response_from_callback (
				-1, 32 * 1024,     /* 32k page size */
				&http_frame_reader, s, &http_free_callback);

		MHD_add_response_header(response, "Content-Type", "image/jpeg");

		ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
		MHD_destroy_response(response);
		return ret;

	} else if(!strcmp(url, "/camera_control.cgi")) {
		if(process_get_param_resolution(connection, &ret))
			return ret;

		const char* q;
		if((q = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "brightness")))
			ctrl_set_value(V4L2_CID_BRIGHTNESS, atoi(q));
		if((q = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "contrast")))
			ctrl_set_value(V4L2_CID_CONTRAST, atoi(q));
		if((q = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "gamma")))
			ctrl_set_value(V4L2_CID_GAMMA, atoi(q));
		if((q = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "autogain")))
			ctrl_set_value(V4L2_CID_AUTOGAIN, atoi(q));
		if((q = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "mode"))) {
			int val = atoi(q);
			switch(val) {
			case 0: ctrl_set_value(V4L2_CID_POWER_LINE_FREQUENCY, V4L2_CID_POWER_LINE_FREQUENCY_50HZ); break;
			case 1: ctrl_set_value(V4L2_CID_POWER_LINE_FREQUENCY, V4L2_CID_POWER_LINE_FREQUENCY_60HZ); break;
			case 2: ctrl_set_value(V4L2_CID_POWER_LINE_FREQUENCY, V4L2_CID_POWER_LINE_FREQUENCY_DISABLED); break;
			default: return mk_response_text(connection, "Invalid mode, valid is: 0 (50 Hz), 1 (60 Hz), 2 (outdoor)");
			}
		}
		if((q = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "sharpness")))
			ctrl_set_value(V4L2_CID_SHARPNESS, atoi(q));
		if((q = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "quality")))
			jpeg_set_quality(atoi(q));

		return mk_response_text(connection, "Configuration applied.");
	}
	//const char* q = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "q");


	printf("File not found: %s (method %s, version %s)\n", url, method, version);
	return mk_response_404(connection);
}


/*******************************************************************************
 *** Command line interface
 ******************************************************************************/

static void usage(FILE * fp, int argc, char ** argv) {
	fprintf(
			fp,
			"Usage: %s [options]\n\n"
					"Options:\n"
					"-d | --device name   Video device name [/dev/video]\n"
					"-h | --help          Print this message\n"
					"-m | --mmap          Use memory mapped buffers\n"
					"-r | --read          Use read() calls\n"
					"-u | --userp         Use application allocated buffers\n"
					"-p | --private       Use private mapping (use with -m)\n"
					"-c | --count         Number of frames to grab\n"
					"-w | --width         Set width (640 or 320), height is auto-selected\n"
#ifdef JPEG_DECODE
					"-j | --decode-jpeg   Decode DC coefficients of JPEG, repeat to save as /tmp/test.pgm\n"
#endif
#ifdef JPEG_SIGN
					"-s | --sign-jpeg     Sign SHA1 hash of JPEG data\n"
#endif
					"-v | --verbose       Be verbose, e.g., print video frames\n"
					, argv[0]);
}

static const char short_options[] = "d:hmrupc:w:jsv";

static const struct option long_options[] = {
	{ "device", required_argument, NULL, 'd' },
	{ "help", no_argument, NULL, 'h' },
	{ "mmap", no_argument, NULL, 'm' },
	{ "read", no_argument, NULL, 'r' },
	{ "userp", no_argument, NULL, 'u' },
	{ "private", no_argument, NULL, 'p' },
	{ "count", required_argument, NULL, 'c' },
	{ "width", required_argument, NULL, 'w' },
#ifdef JPEG_DECODE
	{ "decode-jpeg", no_argument, NULL, 'j' },
#endif
#ifdef JPEG_SIGN
	{ "sign-jpeg", no_argument, NULL, 's' },
#endif
	{ "verbose", no_argument, NULL, 'v' },
	{ 0, 0, 0, 0 }
};

int main(int argc, char ** argv)
{
	for (;;) {
		int index;

		int c = getopt_long(argc, argv, short_options, long_options, &index);
		if(c == -1)
			break;

		switch (c) {
		case 0: /* getopt_long() flag */                                  break;
		case 'd': dev_name = optarg;                                      break;
		case 'h': usage(stdout, argc, argv);                 exit(EXIT_SUCCESS);
		case 'm': io = IO_METHOD_MMAP;                                    break;
		case 'r': io = IO_METHOD_READ;                                    break;
		case 'u': io = IO_METHOD_USERPTR;                                 break;
		case 'p': mmap_flags = MAP_PRIVATE;                               break;
		case 'c': count = atoi(optarg);                                   break;
#ifdef JPEG_DECODE
		case 'j': jpeg_decode++;                                          break;
#endif
#ifdef JPEG_SIGN
		case 's': jpeg_sign = 1;                                          break;
#endif

		case 'w':
			width = atoi(optarg);
			switch (width) {
			case 640:
				height = 480;
				break;
			case 320:
				height = 240;
				break;
			default:
				usage(stderr, argc, argv);
				exit(EXIT_FAILURE);
			}
			break;

		case 'v': verbose = 1;                                            break;
		default: usage(stderr, argc, argv);                  exit(EXIT_FAILURE);
		}
	}

#ifdef JPEG_SIGN
	const char* priv_key = "/etc/private.pem";
	printf("Loading private key from %s\n", priv_key);
	if(load_private_key(priv_key, &rsa_key))
		return 1;
#endif

	printf("init_buffers\n");
	init_buffers();

#ifdef HTTPD
	struct MHD_Daemon *d = MHD_start_daemon(
			// MHD_USE_SELECT_INTERNALLY | MHD_USE_DEBUG | MHD_USE_POLL,
			//MHD_USE_SELECT_INTERNALLY | MHD_USE_DEBUG,
			//MHD_USE_THREAD_PER_CONNECTION | MHD_USE_DEBUG | MHD_USE_POLL,
			MHD_USE_THREAD_PER_CONNECTION | MHD_USE_DEBUG,
			80, NULL, NULL, &http_request_handler, NULL,
			MHD_OPTION_CONNECTION_TIMEOUT, 120, MHD_OPTION_END);
	if (d == NULL)
		return 1;
#endif

	printf("open_device\n");
	open_device();

	// camera restart loop (apply configuration changes)
	do {
		restart_cam = 0;

		printf("init_device\n");
		init_device();

		printf("start_capturing\n");
		start_capturing();

#ifdef ENUM_CONTROLS
		printf("enumerating controls\n");
		enumerate_controls();
#endif

		printf("mainloop\n");
		mainloop();
		if(!verbose) printf("\n");
		printf("mainloop finished, cleaning up\n");

		stop_capturing();
		uninit_device();

	} while(restart_cam);

	destroy_buffers();
	close_device();

#ifdef HTTPD
	MHD_stop_daemon(d);
#endif
#ifdef JPEG_SIGN
	RSA_free(rsa_key);
#endif

	return 0;
}
