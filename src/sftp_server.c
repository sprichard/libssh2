/* Copyright (c) 2010-2015, Liaison Technologies, Inc. (formerly nuBridges, Inc.)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms,
 * with or without modification, are permitted provided
 * that the following conditions are met:
 *
 *   Redistributions of source code must retain the above
 *   copyright notice, this list of conditions and the
 *   following disclaimer.
 *
 *   Redistributions in binary form must reproduce the above
 *   copyright notice, this list of conditions and the following
 *   disclaimer in the documentation and/or other materials
 *   provided with the distribution.
 *
 *   Neither the name of the copyright holder nor the names
 *   of any other contributors may be used to endorse or
 *   promote products derived from this software without
 *   specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
 * CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 */
 
/* The following define used to be in libssh2_sftp.h (as of v1.2.7). */
/* It seems to no longer be necessary, but sftp_server.c is still    */
/* based upon that version. So, this define is required here.        */
/* SEP, Liaison                                                      */
#define LIBSSH2_SFTP_PACKET_MAXLEN  40000

#include <assert.h>

#include "libssh2_priv.h"
#include "libssh2_sftp.h"
#include "libssh2_messages.h"
#include "channel.h"
#include "session.h"
#include "server.h"
#include "messages.h"
#include "sftp.h"
#include <sys/types.h>
#include <dirent.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <pwd.h>
#include <grp.h>
#include <limits.h>
#include <sys/statvfs.h>

int		bufwritten;
int		packet_len;

char	buf[2048];
int		buflen;

char	longentry[1024];

double	libssh2_file_time, libssh2_network_time;
double	libssh2_file_read, libssh2_file_write;
double	libssh2_channel_write_time;
static double	time_in, time_out, time_in2, time_out2;


unsigned char	default_CRLF[3] = {0x0d, 0x0a, 0x00};

// File open options.
int		fmtStream = 0;
int		recordSep = 0;
int		trimBlanks = 0;
int		truncateRecords = 0;
int		formatRecords = 0;
char	lineEnd[3];
char	formatDelim[8];

/* Note: Version 6 was documented at the time of writing
 * However it was marked as "DO NOT IMPLEMENT" due to pending changes
 *
 * This release of libssh2 implements Version 5 with automatic downgrade
 * based on server's declaration
 */

/* SFTP packet types */
#define SSH_FXP_INIT                            1
#define SSH_FXP_VERSION                         2
#define SSH_FXP_OPEN                            3
#define SSH_FXP_CLOSE                           4
#define SSH_FXP_READ                            5
#define SSH_FXP_WRITE                           6
#define SSH_FXP_LSTAT                           7
#define SSH_FXP_FSTAT                           8
#define SSH_FXP_SETSTAT                         9
#define SSH_FXP_FSETSTAT                        10
#define SSH_FXP_OPENDIR                         11
#define SSH_FXP_READDIR                         12
#define SSH_FXP_REMOVE                          13
#define SSH_FXP_MKDIR                           14
#define SSH_FXP_RMDIR                           15
#define SSH_FXP_REALPATH                        16
#define SSH_FXP_STAT                            17
#define SSH_FXP_RENAME                          18
#define SSH_FXP_READLINK                        19
#define SSH_FXP_SYMLINK                         20
#define SSH_FXP_STATUS                          101
#define SSH_FXP_HANDLE                          102
#define SSH_FXP_DATA                            103
#define SSH_FXP_NAME                            104
#define SSH_FXP_ATTRS                           105
#define SSH_FXP_EXTENDED                        200
#define SSH_FXP_EXTENDED_REPLY                  201

#define LIBSSH2_SFTP_HANDLE_FILE        0
#define LIBSSH2_SFTP_HANDLE_DIR         1

/* S_IFREG */
#define LIBSSH2_SFTP_ATTR_PFILETYPE_FILE        0100000
/* S_IFDIR */
#define LIBSSH2_SFTP_ATTR_PFILETYPE_DIR         0040000

#define SSH_FXE_STATVFS_ST_RDONLY               0x00000001
#define SSH_FXE_STATVFS_ST_NOSUID               0x00000002

static int sftp_close_handle(LIBSSH2_SFTP_HANDLE *handle);

/*
 * _libssh2_sftp_locate
 *
 * Locate an SFTP_HANDLE by handle
 */
LIBSSH2_API LIBSSH2_SFTP_HANDLE*
libssh2_sftp_handle_locate(LIBSSH2_SFTP* sftp, char* handle, int handle_len)
{
	LIBSSH2_SFTP_HANDLE*	sftp_handle;

    for(sftp_handle = _libssh2_list_first(&sftp->sftp_handles);
        sftp_handle; sftp_handle = _libssh2_list_next(&sftp_handle->node)) {
		if((sftp_handle->handle_len == handle_len) &&
			(!memcmp(sftp_handle->handle, handle, handle_len)))
			return sftp_handle;
    }
    return NULL;
}

/* sftp_diagnose_errno
 * Return the LIBSSH_FX_error that relates to the passed errno.
 */
static int sftp_diagnose_errno(int errnum)
{
	if (errnum < 1) return errnum;
	switch(errnum) {
		case EBADNAME:
		case ENAMETOOLONG:
		case EINVAL:
			return LIBSSH2_FX_INVALID_FILENAME;
		case ENOENT:
//		case ENOENT1:		// Manual says it exists, compiler says no.
		case EISDIR:
			return LIBSSH2_FX_NO_SUCH_FILE;
		case EACCES:
			return LIBSSH2_FX_PERMISSION_DENIED;
		case EBADDATA:
			return LIBSSH2_FX_BAD_MESSAGE;
		case ENOTCONN:
			return LIBSSH2_FX_NO_CONNECTION;
		case EPIPE:
			return LIBSSH2_FX_CONNECTION_LOST;
		case ENOTOPEN:
		case ENOTREAD:
		case ENOTWRITE:
		case ERECIO:
		case EBADSEEK:
		case EBADMODE:
		case EBADPOS:
		case ENOPOS:
		case ENUMMBRS:
		case ENUMRECS:
		case ENOREC:
		case EPERM:
		case EBUSY:
		case EBADOPT:
		case ENOTUPD:
		case ENOTDLT:
		case EPAD:
		case EBADKEYLN:
		case EPUTANDGET:
		case EGETANDPUT:
		case EIOERROR:
		case EIORECERR:
		case ENOTSUP:
		case ESPIPE:
		case ENOSYS:
			return LIBSSH2_FX_OP_UNSUPPORTED;
		case EBADF:
		case ESTALE:
//		case EBADH:			// Manual says it exists, compiler says no.
			return LIBSSH2_FX_INVALID_HANDLE;
//		case EBADOBJ:		// Manual says it exists, compiler says no
			return LIBSSH2_FX_NO_SUCH_PATH;
		case EEXIST:
			return LIBSSH2_FX_FILE_ALREADY_EXISTS;
		case EROFS:
		case EROOBJ:
			return LIBSSH2_FX_WRITE_PROTECT;
		case ENODEV:
		case ENXIO:
		case EOFFLINE:
			return LIBSSH2_FX_NO_MEDIA;
		case ENOSPC:
			return LIBSSH2_FX_NO_SPACE_ON_FILESYSTEM;
		case EDEADLK:
//		case ENOLOCK:		// Manual says it exists, compiler says no
		case ELOCKED:
			return LIBSSH2_FX_LOCK_CONFLICT;
		case ENOTEMPTY:
			return LIBSSH2_FX_DIR_NOT_EMPTY;
		case ENOTDIR:
//		case EBADDIR:		// Manual says it exists, compiler says no
			return LIBSSH2_FX_NOT_A_DIRECTORY;
		case EXDEV:
//		case ERECURSE:		// Manual says it exists, compiler says no
		case ELOOP:
			return LIBSSH2_FX_LINK_LOOP;
		case EFBIG:
			return LIBSSH2_FX_QUOTA_EXCEEDED;
		default:
			return LIBSSH2_FX_FAILURE;
			return LIBSSH2_FX_EOF;
			return LIBSSH2_FX_UNKNOWN_PRINCIPAL;
	}
}

/* sftp_attrsize
 * Size that attr with this flagset will occupy when turned into a bin struct
 */
static int sftp_attrsize(unsigned long flags)
{
    return (4 +                                 /* flags(4) */
            ((flags & LIBSSH2_SFTP_ATTR_SIZE) ? 8 : 0) +
            ((flags & LIBSSH2_SFTP_ATTR_UIDGID) ? 8 : 0) +
            ((flags & LIBSSH2_SFTP_ATTR_PERMISSIONS) ? 4 : 0) +
            ((flags & LIBSSH2_SFTP_ATTR_ACMODTIME) ? 8 : 0));
                                                /* atime + mtime as u32 */
}

/* _libssh2_store_u64
 */
static void _libssh2_store_u64(unsigned char **ptr, libssh2_uint64_t value)
{
    uint32_t msl = (uint32_t)(value >> 32);
    unsigned char *buf = *ptr;

    buf[0] = (unsigned char)((msl >> 24) & 0xFF);
    buf[1] = (unsigned char)((msl >> 16) & 0xFF);
    buf[2] = (unsigned char)((msl >> 8)  & 0xFF);
    buf[3] = (unsigned char)( msl        & 0xFF);

    buf[4] = (unsigned char)((value >> 24) & 0xFF);
    buf[5] = (unsigned char)((value >> 16) & 0xFF);
    buf[6] = (unsigned char)((value >> 8)  & 0xFF);
    buf[7] = (unsigned char)( value        & 0xFF);

    *ptr += 8;
}

/*
 * sftp_packet_add
 *
 * Add a packet to the SFTP packet brigade
 */
static int
sftp_packet_add(LIBSSH2_SFTP *sftp, unsigned char *data,
                size_t data_len)
{
    LIBSSH2_SESSION *session = sftp->channel->session;
    LIBSSH2_PACKET *packet;

    _libssh2_debug(session, LIBSSH2_TRACE_SFTP, "Received packet %d (len %d)",
                   (int) data[0], data_len);
    packet = LIBSSH2_ALLOC(session, sizeof(LIBSSH2_PACKET));
    if (!packet) {
        return _libssh2_error(session, LIBSSH2_ERROR_ALLOC,
                              "Unable to allocate datablock for SFTP packet");
    }
    memset(packet, 0, sizeof(LIBSSH2_PACKET));

    packet->data = data;
    packet->data_len = data_len;
    packet->data_head = 5;

    _libssh2_list_add(&sftp->packets, &packet->node);

    return 0;
}

/*
 * sftp_packet_read
 *
 * Frame an SFTP packet off the channel
 */
static int
sftp_packet_read(LIBSSH2_SFTP *sftp)
{
    LIBSSH2_CHANNEL *channel = sftp->channel;
    LIBSSH2_SESSION *session = channel->session;
    unsigned char buffer[4];    /* To store the packet length */
    unsigned char *packet;
    size_t packet_len, packet_received;
    ssize_t bytes_received;
    int rc;

    _libssh2_debug(session, LIBSSH2_TRACE_SFTP, "recv packet");

    /* If there was a previous partial, start using it */
    if (sftp->partial_packet) {

        packet = sftp->partial_packet;
        packet_len = sftp->partial_len;
        packet_received = sftp->partial_received;
        sftp->partial_packet = NULL;

        _libssh2_debug(session, LIBSSH2_TRACE_SFTP,
                       "partial read cont, len: %lu", packet_len);
    }
    else {
        rc = _libssh2_channel_read(channel, 0, (char *) buffer, 4);
        if (rc == LIBSSH2_ERROR_EAGAIN) {
            return rc;
        }
        else if (4 != rc) {
            /* TODO: this is stupid since we can in fact get 1-3 bytes in a
               legitimate working case as well if the connection happens to be
               super slow or something */
            return _libssh2_error(session, LIBSSH2_ERROR_CHANNEL_FAILURE,
                                  "Read part of packet");
        }

        packet_len = _libssh2_ntohu32(buffer);
        _libssh2_debug(session, LIBSSH2_TRACE_SFTP,
                       "Data begin - Packet Length: %lu", packet_len);
        if (packet_len > LIBSSH2_SFTP_PACKET_MAXLEN) {
            return _libssh2_error(session, LIBSSH2_ERROR_CHANNEL_PACKET_EXCEEDED,
                                  "SFTP packet too large");
        }

        packet = LIBSSH2_ALLOC(session, packet_len);
        if (!packet) {
            return _libssh2_error(session, LIBSSH2_ERROR_ALLOC,
                                  "Unable to allocate SFTP packet");
        }

        packet_received = 0;
    }

    /* Read as much of the packet as we can */
    while (packet_len > packet_received) {
        bytes_received =
            _libssh2_channel_read(channel, 0,
                                  (char *) packet + packet_received,
                                  packet_len - packet_received);

        if (bytes_received == LIBSSH2_ERROR_EAGAIN) {
            /*
             * We received EAGAIN, save what we have and
             * return to EAGAIN to the caller
             */
            sftp->partial_packet = packet;
            sftp->partial_len = packet_len;
            sftp->partial_received = packet_received;
            packet = NULL;

            return bytes_received;
        }
        else if (bytes_received < 0) {
            LIBSSH2_FREE(session, packet);
            return _libssh2_error(session, bytes_received,
                                  "Receive error waiting for SFTP packet");
        }
        packet_received += bytes_received;
    }

    rc = sftp_packet_add(sftp, packet, packet_len);
    if (rc) {
        LIBSSH2_FREE(session, packet);
        return rc;
    }

    return packet[0];
}

/*
 * sftp_packet_ask()
 *
 * Checks if there's a matching SFTP packet available.
 */
static int
sftp_packet_ask(LIBSSH2_SFTP *sftp, unsigned char packet_type,
                int request_id, unsigned char **data,
                size_t *data_len)
{
    LIBSSH2_SESSION *session = sftp->channel->session;
    LIBSSH2_PACKET *packet = _libssh2_list_first(&sftp->packets);
    unsigned char match_buf[5];
    int match_len;

    _libssh2_debug(session, LIBSSH2_TRACE_SFTP, "Asking for %d packet",
                   (int) packet_type);

    match_buf[0] = packet_type;
//    if ((packet_type == SSH_FXP_VERSION) ||
//		(packet_type == SSH_FXP_INIT)) {
        /* Special consideration when matching INIT/VERSION packets */
        match_len = 1;
//    } else {
//        match_len = 5;
//        _libssh2_htonu32(match_buf + 1, request_id);
//    }

    while (packet) {
        if (!memcmp((char *) packet->data, (char *) match_buf, match_len)) {

            /* Match! Fetch the data */
            *data = packet->data;
            *data_len = packet->data_len;
			sftp->request_id = _libssh2_ntohu32(packet->data + 1);

            /* unlink and free this struct */
            _libssh2_list_remove(&packet->node);
            LIBSSH2_FREE(session, packet);

            return 0;
        }
        /* check next struct in the list */
        packet = _libssh2_list_next(&packet->node);
    }
    return -1;
}

/* sftp_packet_require
 * A la libssh2_packet_require
 */
static int
sftp_packet_require(LIBSSH2_SFTP *sftp, unsigned char packet_type,
                    int request_id, unsigned char **data,
                    size_t *data_len)
{
    LIBSSH2_SESSION *session = sftp->channel->session;
    int ret;

    _libssh2_debug(session, LIBSSH2_TRACE_SFTP, "Requiring packet %d id %ld",
                   (int) packet_type, request_id);

    if (sftp_packet_ask(sftp, packet_type, request_id, data, data_len) == 0) {
        /* The right packet was available in the packet brigade */
        _libssh2_debug(session, LIBSSH2_TRACE_SFTP, "Got %d",
                       (int) packet_type);
        return 0;
    }

    while (session->socket_state == LIBSSH2_SOCKET_CONNECTED) {
        ret = sftp_packet_read(sftp);
        if (ret == LIBSSH2_ERROR_EAGAIN) {
            return ret;
        } else if (ret <= 0) {
            return -1;
        }

        /* data was read, check the queue again */
        if (!sftp_packet_ask(sftp, packet_type, request_id, data, data_len)) {
            /* The right packet was available in the packet brigade */
            _libssh2_debug(session, LIBSSH2_TRACE_SFTP, "Got %d",
                           (int) packet_type);
            return 0;
        }
    }

    /* Only reached if the socket died */
    return LIBSSH2_ERROR_SOCKET_DISCONNECT;
}

/* sftp_packet_requirev
 * Require one of N possible reponses
 */
static int
sftp_packet_requirev(LIBSSH2_SFTP *sftp, int num_valid_responses,
                     const unsigned char *valid_responses,
                     int request_id, unsigned char **data,
                     size_t *data_len)
{
    int i;
    int ret;

    /* If no timeout is active, start a new one */
    if (sftp->requirev_start == 0) {
        sftp->requirev_start = time(NULL);
    }

    while (sftp->channel->session->socket_state == LIBSSH2_SOCKET_CONNECTED) {
        for(i = 0; i < num_valid_responses; i++) {
            if (sftp_packet_ask(sftp, valid_responses[i], request_id,
                                data, data_len) == 0) {
                /*
                 * Set to zero before all returns to say
                 * the timeout is not active
                 */
                sftp->requirev_start = 0;
                return 0;
            }
        }

        ret = sftp_packet_read(sftp);
        if ((ret < 0) && (ret != LIBSSH2_ERROR_EAGAIN)) {
            sftp->requirev_start = 0;
            return -1;
        } else if (ret <= 0) {
            /* prevent busy-looping */
            long left =
                LIBSSH2_READ_TIMEOUT - (long)(time(NULL) - sftp->requirev_start);

            if (left <= 0) {
                sftp->requirev_start = 0;
                return LIBSSH2_ERROR_TIMEOUT;
            }
            else if (ret == LIBSSH2_ERROR_EAGAIN) {
                return ret;
            }
        }
    }

    sftp->requirev_start = 0;
    return -1;
}

/* sftp_attr2bin
 * Populate attributes into an SFTP block
 */
static int
sftp_attr2bin(unsigned char *p, const LIBSSH2_SFTP_ATTRIBUTES * attrs)
{
    unsigned char *s = p;
    uint32_t flag_mask =
        LIBSSH2_SFTP_ATTR_SIZE | LIBSSH2_SFTP_ATTR_UIDGID |
        LIBSSH2_SFTP_ATTR_PERMISSIONS | LIBSSH2_SFTP_ATTR_ACMODTIME;

    /* TODO: When we add SFTP4+ functionality flag_mask can get additional
       bits */

    if (!attrs) {
        _libssh2_htonu32(s, 0);
        return 4;
    }

    _libssh2_store_u32(&s, attrs->flags & flag_mask);

    if (attrs->flags & LIBSSH2_SFTP_ATTR_SIZE) {
        _libssh2_store_u64(&s, attrs->filesize);
    }

    if (attrs->flags & LIBSSH2_SFTP_ATTR_UIDGID) {
        _libssh2_store_u32(&s, attrs->uid);
        _libssh2_store_u32(&s, attrs->gid);
    }

    if (attrs->flags & LIBSSH2_SFTP_ATTR_PERMISSIONS) {
        _libssh2_store_u32(&s, attrs->permissions);
    }

    if (attrs->flags & LIBSSH2_SFTP_ATTR_ACMODTIME) {
        _libssh2_store_u32(&s, attrs->atime);
        _libssh2_store_u32(&s, attrs->mtime);
    }

    return (s - p);
}

/* sftp_bin2attr
 */
static int
sftp_bin2attr(LIBSSH2_SFTP_ATTRIBUTES * attrs, const unsigned char *p)
{
    const unsigned char *s = p;

    memset(attrs, 0, sizeof(LIBSSH2_SFTP_ATTRIBUTES));
    attrs->flags = _libssh2_ntohu32(s);
    s += 4;

    if (attrs->flags & LIBSSH2_SFTP_ATTR_SIZE) {
        attrs->filesize = _libssh2_ntohu64(s);
        s += 8;
    }

    if (attrs->flags & LIBSSH2_SFTP_ATTR_UIDGID) {
        attrs->uid = _libssh2_ntohu32(s);
        s += 4;
        attrs->gid = _libssh2_ntohu32(s);
        s += 4;
    }

    if (attrs->flags & LIBSSH2_SFTP_ATTR_PERMISSIONS) {
        attrs->permissions = _libssh2_ntohu32(s);
        s += 4;
    }

    if (attrs->flags & LIBSSH2_SFTP_ATTR_ACMODTIME) {
        attrs->atime = _libssh2_ntohu32(s);
        s += 4;
        attrs->mtime = _libssh2_ntohu32(s);
        s += 4;
    }

    return (s - p);
}

/* sftp_stat2attr
 */
static int
sftp_stat2attr(LIBSSH2_SFTP_ATTRIBUTES * attrs, struct stat* sb)
{
    memset(attrs, 0, sizeof(LIBSSH2_SFTP_ATTRIBUTES));

	attrs->filesize = sb->st_size;
	attrs->flags |= LIBSSH2_SFTP_ATTR_SIZE;

	attrs->uid = sb->st_uid;
	attrs->gid = sb->st_gid;
	attrs->flags |= LIBSSH2_SFTP_ATTR_UIDGID;

	if (S_ISDIR(sb->st_mode)) attrs->permissions |= LIBSSH2_SFTP_S_IFDIR;
	if (S_ISREG(sb->st_mode)) attrs->permissions |= LIBSSH2_SFTP_S_IFREG;
	if (S_ISLNK(sb->st_mode)) attrs->permissions |= LIBSSH2_SFTP_S_IFLNK;
	if (S_ISFIFO(sb->st_mode)) attrs->permissions |= LIBSSH2_SFTP_S_IFIFO;
	if (S_ISCHR(sb->st_mode)) attrs->permissions |= LIBSSH2_SFTP_S_IFCHR;
	if (S_ISBLK(sb->st_mode)) attrs->permissions |= LIBSSH2_SFTP_S_IFBLK;
	if (S_ISSOCK(sb->st_mode)) attrs->permissions |= LIBSSH2_SFTP_S_IFSOCK;
	if (sb->st_mode & S_IRUSR) attrs->permissions |= LIBSSH2_SFTP_S_IRUSR;
	if (sb->st_mode & S_IWUSR) attrs->permissions |= LIBSSH2_SFTP_S_IWUSR;
	if (sb->st_mode & S_IXUSR) attrs->permissions |= LIBSSH2_SFTP_S_IXUSR;
	if (sb->st_mode & S_IRGRP) attrs->permissions |= LIBSSH2_SFTP_S_IRGRP;
	if (sb->st_mode & S_IWGRP) attrs->permissions |= LIBSSH2_SFTP_S_IWGRP;
	if (sb->st_mode & S_IXGRP) attrs->permissions |= LIBSSH2_SFTP_S_IXGRP;
	if (sb->st_mode & S_IROTH) attrs->permissions |= LIBSSH2_SFTP_S_IROTH;
	if (sb->st_mode & S_IWOTH) attrs->permissions |= LIBSSH2_SFTP_S_IWOTH;
	if (sb->st_mode & S_IXOTH) attrs->permissions |= LIBSSH2_SFTP_S_IXOTH;
	attrs->flags |= LIBSSH2_SFTP_ATTR_PERMISSIONS;

	attrs->atime = sb->st_atime;
	attrs->mtime = sb->st_mtime;
	attrs->flags |= LIBSSH2_SFTP_ATTR_ACMODTIME;

    return 0;
}

static int
sftp_attr2stat(LIBSSH2_SFTP_ATTRIBUTES * attrs, struct stat* sb)
{
    memset(sb, 0, sizeof(struct stat));

	if (attrs->flags & LIBSSH2_SFTP_ATTR_SIZE)
		sb->st_size = attrs->filesize;

	if (attrs->flags & LIBSSH2_SFTP_ATTR_SIZE) {
		sb->st_uid = attrs->uid;
		sb->st_gid = attrs->gid;
	}

	if (attrs->flags & LIBSSH2_SFTP_ATTR_PERMISSIONS) {
		if (LIBSSH2_SFTP_S_ISDIR(attrs->permissions)) sb->st_mode = _S_IFDIR;
		if (LIBSSH2_SFTP_S_ISREG(attrs->permissions)) sb->st_mode = _S_IFREG;
		if (LIBSSH2_SFTP_S_ISLNK(attrs->permissions)) sb->st_mode = _S_IFLNK;
		if (LIBSSH2_SFTP_S_ISFIFO(attrs->permissions)) sb->st_mode = _S_IFFIFO;
		if (LIBSSH2_SFTP_S_ISCHR(attrs->permissions)) sb->st_mode = _S_IFCHR;
		if (LIBSSH2_SFTP_S_ISBLK(attrs->permissions)) sb->st_mode = _S_IFBLK;
		if (LIBSSH2_SFTP_S_ISSOCK(attrs->permissions)) sb->st_mode = _S_IFSOCK;
		if (attrs->permissions & LIBSSH2_SFTP_S_IRUSR) sb->st_mode |= S_IRUSR;
		if (attrs->permissions & LIBSSH2_SFTP_S_IWUSR) sb->st_mode |= S_IWUSR;
		if (attrs->permissions & LIBSSH2_SFTP_S_IXUSR) sb->st_mode |= S_IXUSR;
		if (attrs->permissions & LIBSSH2_SFTP_S_IRGRP) sb->st_mode |= S_IRGRP;
		if (attrs->permissions & LIBSSH2_SFTP_S_IWGRP) sb->st_mode |= S_IWGRP;
		if (attrs->permissions & LIBSSH2_SFTP_S_IXGRP) sb->st_mode |= S_IXGRP;
		if (attrs->permissions & LIBSSH2_SFTP_S_IROTH) sb->st_mode |= S_IROTH;
		if (attrs->permissions & LIBSSH2_SFTP_S_IWOTH) sb->st_mode |= S_IWOTH;
		if (attrs->permissions & LIBSSH2_SFTP_S_IXOTH) sb->st_mode |= S_IXOTH;
	}

	if (attrs->flags & LIBSSH2_SFTP_ATTR_ACMODTIME) {
		sb->st_atime = attrs->atime;
		sb->st_mtime = attrs->mtime;
	}

    return 0;
}

static int
sftp_make_longentry(const char* path, int path_len, struct stat* sb)
{
	LIBSSH2_SFTP_ATTRIBUTES attrs = {
        LIBSSH2_SFTP_ATTR_PERMISSIONS, 0, 0, 0, 0, 0, 0
    };
    int retcode, rc, x;
    unsigned char *data, *s, *p;
	char	this_year[5];
	time_t	timeval;
	struct group grp;
	struct group * grpptr=&grp;
	struct group * tempGrpPtr;
	char grpbuffer[1024];
	int  grplinelen = sizeof(grpbuffer);
	struct passwd pd;
	struct passwd* pwdptr=&pd;
	struct passwd* tempPwdPtr;
	char pwdbuffer[200];
	unsigned char	buffer[2048];
	unsigned char*	bufptr = buffer;
	int  pwdlinelen = sizeof(pwdbuffer);

	timeval = time(&timeval);
	memset(this_year, 0, sizeof(this_year));
	sprintf(pwdbuffer, "%s", ctime(&timeval));
	memcpy(this_year, pwdbuffer+20, 4);

	memset(longentry, ' ', sizeof(longentry));
	p = longentry;
	memcpy(p, "----------", 10);
	if (S_ISDIR(sb->st_mode)) *p = 'd';
	else if (S_ISREG(sb->st_mode)) *p = '-';
	else if (S_ISLNK(sb->st_mode)) *p = 'l';
	p++;
	if (sb->st_mode & S_IRUSR) *p = 'r';
	p++;
	if (sb->st_mode & S_IWUSR) *p = 'w';
	p++;
	if (sb->st_mode & S_IXUSR) *p = 'x';
	p++;
	if (sb->st_mode & S_IRGRP) *p = 'r';
	p++;
	if (sb->st_mode & S_IWGRP) *p = 'w';
	p++;
	if (sb->st_mode & S_IXGRP) *p = 'x';
	p++;
	if (sb->st_mode & S_IROTH) *p = 'r';
	p++;
	if (sb->st_mode & S_IWOTH) *p = 'w';
	p++;
	if (sb->st_mode & S_IXOTH) *p = 'x';
	p += 6;
	sprintf(buffer, "%i", sb->st_nlink);
	p -= strlen(buffer);
	memcpy(p, buffer, strlen(buffer));
	p += strlen(buffer) + 1;
	if ((getpwuid_r(sb->st_uid,pwdptr,pwdbuffer,pwdlinelen,
					&tempPwdPtr)) == 0) {
		sprintf(buffer, "%s", pd.pw_name);
		x = strlen(buffer);
		if (x > 12) x = 12;
		memcpy(p, buffer, x);
	} else {
		sprintf(buffer, "%i", sb->st_uid);
		memcpy(p, buffer, strlen(buffer));
	}
	p += 13;
	if ((getgrgid_r(sb->st_gid,grpptr,grpbuffer,grplinelen,
					&tempGrpPtr)) == 0) {
		sprintf(buffer, "%s", grp.gr_name);
		x = strlen(buffer);
		if (x > 12) x = 12;
		memcpy(p, buffer, x);
	} else {
		sprintf(buffer, "%i", sb->st_gid);
		memcpy(p, buffer, strlen(buffer));
	}
	p += 21;
	sprintf(buffer, "%lld", sb->st_size);
	p -= strlen(buffer);
	memcpy(p, buffer, strlen(buffer));
	p += strlen(buffer) + 1;
	ctime_r(&sb->st_mtime, bufptr);
	buffer[16] = '\0';
	if (memcmp(buffer+20, this_year, 4)) {
		buffer[11] = ' ';
		memcpy(buffer+12, buffer+20, 4);
	}
	memcpy(p, buffer + 4, strlen(buffer + 4));
	p += strlen(buffer + 4) + 1;
	memcpy(p, path, path_len);
	p += path_len;
	*p = 0;
	return 0;
}


/* ************
 * SFTP API *
 ************ */

LIBSSH2_CHANNEL_CLOSE_FUNC(libssh2_sftp_dtor);

/* libssh2_sftp_dtor
 * Shutdown an SFTP stream when the channel closes
 */
LIBSSH2_CHANNEL_CLOSE_FUNC(libssh2_sftp_dtor)
{
    LIBSSH2_SFTP *sftp = (LIBSSH2_SFTP *) (*channel_abstract);

    (void) session_abstract;
    (void) channel;

    /* Free the partial packet storage for sftp_packet_read */
    if (sftp->partial_packet) {
        LIBSSH2_FREE(session, sftp->partial_packet);
    }

    /* Free the packet storage for _libssh2_sftp_packet_readdir */
    if (sftp->readdir_packet) {
        LIBSSH2_FREE(session, sftp->readdir_packet);
    }

    LIBSSH2_FREE(session, sftp);
}

/*
 * sftp_init
 *
 * Startup an SFTP session
 */
static LIBSSH2_SFTP *sftp_init(LIBSSH2_CHANNEL *sftp_channel)
{
    unsigned char *data, *s;
    size_t data_len;
    int rc;
    LIBSSH2_SFTP*		sftp;
	LIBSSH2_SESSION*	session;

	session = sftp_channel->session;

	if (session->sftpInit_state == libssh2_NB_state_idle) {

        sftp = session->sftpInit_sftp =
            LIBSSH2_ALLOC(session, sizeof(LIBSSH2_SFTP));
        if (!sftp) {
            _libssh2_error(session, LIBSSH2_ERROR_ALLOC,
                           "Unable to allocate a new SFTP structure");
            goto sftp_init_error;
        }
        memset(sftp, 0, sizeof(LIBSSH2_SFTP));
        sftp->channel = sftp_channel;
        sftp->request_id = 0;
        session->sftpInit_state = libssh2_NB_state_created;
    }

	if (session->sftpInit_state == libssh2_NB_state_created) {
		rc = sftp_packet_require(sftp, SSH_FXP_INIT,
                                         sftp->read_request_id, 
										 &sftp->read_packet,
                                         &sftp->read_total_read);
		if (rc == LIBSSH2_ERROR_EAGAIN) {
			_libssh2_error(session, LIBSSH2_ERROR_EAGAIN,
				"Would block waiting for SFTP INIT");
			return NULL;
		} else if (rc) {
			_libssh2_error(session, LIBSSH2_ERROR_SOCKET_TIMEOUT,
				"Timeout waiting for SFTP INIT");
			goto sftp_init_error;
		}
		if (sftp->read_total_read < 5) {
			_libssh2_error(session, LIBSSH2_ERROR_SFTP_PROTOCOL,
				"Invalid SSH_FXP_INIT request");
			goto sftp_init_error;
		}
        session->sftpInit_state = libssh2_NB_state_sent;
    }

    if (session->sftpInit_state == libssh2_NB_state_sent) {

		s = sftp->read_packet + 1;
		sftp->version = _libssh2_ntohu32(s);
		s += 4;

        _libssh2_htonu32(session->sftpInit_buffer, 5);
        session->sftpInit_buffer[4] = SSH_FXP_VERSION;
        _libssh2_htonu32(session->sftpInit_buffer + 5, LIBSSH2_SFTP_VERSION);
        session->sftpInit_sent = 0; /* nothing's sent yet */


        _libssh2_debug(session, LIBSSH2_TRACE_SFTP,
                       "Sending FXP_VERSION packet advertising version %d support",
                       (int) LIBSSH2_SFTP_VERSION);

        session->sftpInit_state = libssh2_NB_state_sent1;
    }

	 if (session->sftpInit_state == libssh2_NB_state_sent1) {
         rc = _libssh2_channel_write(sftp_channel, 0,
                                    (char *)session->sftpInit_buffer +
                                    session->sftpInit_sent,
                                    9 - session->sftpInit_sent);
        if (rc == LIBSSH2_ERROR_EAGAIN) {
            _libssh2_error(session, LIBSSH2_ERROR_EAGAIN,
                           "Would block sending SSH_FXP_VERSION");
            return NULL;
        }
        else if(rc < 0) {
            _libssh2_error(session, LIBSSH2_ERROR_SOCKET_SEND,
                           "Unable to send SSH_FXP_VERSION");
            goto sftp_init_error;
        }
        else {
            /* add up the number of bytes sent */
            session->sftpInit_sent += rc;

            if(session->sftpInit_sent == 9)
                /* move on */
                session->sftpInit_state = libssh2_NB_state_sent2;

            /* if less than 9, we remain in this state to send more later on */
        }
	 }

	 if (session->sftpInit_state == libssh2_NB_state_sent2) {
		 sftp->request_id = -1;
		 session->sftpInit_state = libssh2_NB_state_idle;
		 return sftp;
	 }

  sftp_init_error:
    while (_libssh2_channel_free(sftp_channel) ==
           LIBSSH2_ERROR_EAGAIN);
    if (session->sftpInit_sftp) {
        LIBSSH2_FREE(session, session->sftpInit_sftp);
        session->sftpInit_sftp = NULL;
    }
    session->sftpInit_state = libssh2_NB_state_idle;
    return NULL;
}

/*
 * libssh2_sftp_server_init
 *
 * Startup an SFTP server session
 */
LIBSSH2_API LIBSSH2_SFTP *libssh2_sftp_server_init(LIBSSH2_CHANNEL* sftp_channel)
{
    LIBSSH2_SFTP*		ptr;
	LIBSSH2_SESSION*	session;
	
    if(!sftp_channel)
        return NULL;

	session = sftp_channel->session;

    if(!(session->state & LIBSSH2_STATE_AUTHENTICATED)) {
        _libssh2_error(session, LIBSSH2_ERROR_INVAL,
                       "session not authenticated yet");
        return NULL;
    }

    BLOCK_ADJUST_ERRNO(ptr, session, sftp_init(sftp_channel));
    return ptr;
}

/*
 * sftp_shutdown
 *
 * Shutdown the SFTP subsystem
 */
static int
sftp_shutdown(LIBSSH2_SFTP *sftp)
{
    int rc;
    LIBSSH2_SESSION *session = sftp->channel->session;
    /*
     * Make sure all memory used in the state variables are free
     */
    if (sftp->partial_packet) {
        LIBSSH2_FREE(session, sftp->partial_packet);
        sftp->partial_packet = NULL;
    }
    if (sftp->open_packet) {
        LIBSSH2_FREE(session, sftp->open_packet);
        sftp->open_packet = NULL;
    }
    if (sftp->readdir_packet) {
        LIBSSH2_FREE(session, sftp->readdir_packet);
        sftp->readdir_packet = NULL;
    }
    if (sftp->write_packet) {
        LIBSSH2_FREE(session, sftp->write_packet);
        sftp->write_packet = NULL;
    }
    if (sftp->fstat_packet) {
        LIBSSH2_FREE(session, sftp->fstat_packet);
        sftp->fstat_packet = NULL;
    }
    if (sftp->unlink_packet) {
        LIBSSH2_FREE(session, sftp->unlink_packet);
        sftp->unlink_packet = NULL;
    }
    if (sftp->rename_packet) {
        LIBSSH2_FREE(session, sftp->rename_packet);
        sftp->rename_packet = NULL;
    }
    if (sftp->fstatvfs_packet) {
        LIBSSH2_FREE(session, sftp->fstatvfs_packet);
        sftp->fstatvfs_packet = NULL;
    }
    if (sftp->statvfs_packet) {
        LIBSSH2_FREE(session, sftp->statvfs_packet);
        sftp->statvfs_packet = NULL;
    }
    if (sftp->mkdir_packet) {
        LIBSSH2_FREE(session, sftp->mkdir_packet);
        sftp->mkdir_packet = NULL;
    }
    if (sftp->rmdir_packet) {
        LIBSSH2_FREE(session, sftp->rmdir_packet);
        sftp->rmdir_packet = NULL;
    }
    if (sftp->stat_packet) {
        LIBSSH2_FREE(session, sftp->stat_packet);
        sftp->stat_packet = NULL;
    }
    if (sftp->symlink_packet) {
        LIBSSH2_FREE(session, sftp->symlink_packet);
        sftp->symlink_packet = NULL;
    }

    /* TODO: We should consider walking over the sftp_handles list and kill
     * any remaining sftp handles ... */

    rc = _libssh2_channel_free(sftp->channel);

	LIBSSH2_FREE(session, sftp);

    return rc;
}

/* libssh2_sftp_shutdown
 * Shutsdown the SFTP subsystem
 */
LIBSSH2_API int
libssh2_sftp_shutdown(LIBSSH2_SFTP *sftp)
{
    int rc;
    if(!sftp)
        return LIBSSH2_ERROR_BAD_USE;
    BLOCK_ADJUST(rc, sftp->channel->session, sftp_shutdown(sftp));
    return rc;
}

/*
 * sftp_get_request
 *
 * Get an SFTP Client request message.
 */
static LIBSSH2_MESSAGE *sftp_get_request(LIBSSH2_SFTP *sftp)
{
	static const unsigned char request_types[25] =
            { SSH_FXP_OPEN, SSH_FXP_CLOSE, SSH_FXP_READ, SSH_FXP_WRITE,
			SSH_FXP_LSTAT, SSH_FXP_FSTAT, SSH_FXP_SETSTAT, SSH_FXP_FSETSTAT,
			SSH_FXP_OPENDIR, SSH_FXP_READDIR, SSH_FXP_REMOVE, SSH_FXP_MKDIR,
			SSH_FXP_RMDIR, SSH_FXP_REALPATH, SSH_FXP_STAT, SSH_FXP_RENAME,
			SSH_FXP_READLINK, SSH_FXP_SYMLINK, SSH_FXP_STATUS, SSH_FXP_HANDLE,
			SSH_FXP_DATA, SSH_FXP_NAME, SSH_FXP_ATTRS, SSH_FXP_EXTENDED,
			SSH_FXP_EXTENDED_REPLY };
    unsigned char *data, *s;
    size_t data_len;
    int rc;
	LIBSSH2_MESSAGE*	message;
	LIBSSH2_SESSION*	session;
	LIBSSH2_CHANNEL*	channel;

	channel = sftp->channel;
	session = channel->session;

	if (sftp->request_state == libssh2_NB_state_idle) {
		message = LIBSSH2_ALLOC(session, sizeof(LIBSSH2_MESSAGE));
		if (!message) {
			_libssh2_error(session, LIBSSH2_ERROR_ALLOC,
				"Unable to allocate space for message structure");
			return NULL;
		}
		memset(message, 0, sizeof(LIBSSH2_MESSAGE));
		message->sftp = sftp;
		message->session = session;
        sftp->request_id++;
        sftp->request_state = libssh2_NB_state_created;
    }

	if (sftp->request_packet) {
		// Free the last request packet received.
		LIBSSH2_FREE(session, sftp->request_packet);
		sftp->request_packet = NULL;
		sftp->request_packet_len = 0;
	}

	if (sftp->request_state == libssh2_NB_state_created) {
		rc = sftp_packet_requirev(sftp, 25, request_types,
                                  sftp->request_id, &sftp->request_packet,
                                  &sftp->request_packet_len);
		if (rc == LIBSSH2_ERROR_EAGAIN) {
			_libssh2_error(session, LIBSSH2_ERROR_EAGAIN,
				"Would block waiting for SFTP request");
			return NULL;
		}
		if (rc && (channel->remote.eof) && (!channel->remote.close)) {
			rc = LIBSSH2_ERROR_EAGAIN;
			_libssh2_error(session, LIBSSH2_ERROR_EAGAIN,
				"Remote EOF received for channel.");
			return NULL;

		} else if (rc && (!channel->remote.close)) {
			_libssh2_error(session, LIBSSH2_ERROR_SOCKET_TIMEOUT,
				"Timeout waiting for SFTP request");
			goto sftp_request_error;
		}
        sftp->request_state = libssh2_NB_state_sent;
	}

	if (sftp->request_state == libssh2_NB_state_sent) {
		if (!channel->remote.close) {
			message->request_id = _libssh2_ntohu32(sftp->request_packet + 1);
			message->msg_ptr = sftp->request_packet;
			message->msg_len = sftp->request_packet_len;
			message->offset = 1;
			message->type = sftp->request_packet[0];
			assert(message->request_id == sftp->request_id);
		}

		sftp->request_state = libssh2_NB_state_sent1;
	}

	if (sftp->request_state == libssh2_NB_state_sent1) {
		sftp->request_state = libssh2_NB_state_idle;
		return message;
	}

sftp_request_error:
    if (message) {
        LIBSSH2_FREE(session, message);
        session->sftpInit_sftp = NULL;
    }
    sftp->request_state = libssh2_NB_state_idle;
    return NULL;
}

/*
 * libssh2_sftp_server_request
 *
 * Get and SFTP client request message.
 */
LIBSSH2_API LIBSSH2_MESSAGE *libssh2_sftp_server_request(LIBSSH2_SFTP *sftp)
{
    LIBSSH2_MESSAGE*	message;
	
    if(!sftp)
        return NULL;


    if(!(sftp->channel->session->state & LIBSSH2_STATE_AUTHENTICATED)) {
        _libssh2_error(sftp->channel->session, LIBSSH2_ERROR_INVAL,
                       "session not authenticated yet");
        return NULL;
    }

    BLOCK_ADJUST_ERRNO(message, sftp->channel->session, sftp_get_request(sftp));
    return message;
}

/*
 * sftp_send_status
 *
 * Send SFTP status message.
 */
static int sftp_send_status(LIBSSH2_SFTP *sftp, int error_code)
{
	char*	s;
	int					rc = -1;
	LIBSSH2_SESSION*	session;
	LIBSSH2_CHANNEL*	channel;
	
    if(!sftp)
        return rc;
	channel = sftp->channel;
	session = channel->session;

	if (sftp->send_state == libssh2_NB_state_idle) {
		sftp->send_packet_len = 13;
		if (!sftp->status_packet) {
			sftp->status_packet = LIBSSH2_ALLOC(session, sftp->send_packet_len);
		}
		s = sftp->status_packet;
		_libssh2_store_u32(&s, sftp->send_packet_len - 4);
		*(s++) = SSH_FXP_STATUS;
		_libssh2_store_u32(&s, sftp->request_id);
		_libssh2_store_u32(&s, error_code);
		
		sftp->send_packet_sent = 0;
		sftp->send_state = libssh2_NB_state_created;
	}

	if (sftp->send_state == libssh2_NB_state_created) {
		do {
//			rc = _libssh2_channel_write(channel, 0,
			rc = libssh2_channel_write_ex(channel, 0,
                         (char *)sftp->status_packet +
                          sftp->send_packet_sent,
		                  sftp->send_packet_len - sftp->send_packet_sent);
	        if (rc == LIBSSH2_ERROR_EAGAIN) {
				_libssh2_error(session, LIBSSH2_ERROR_EAGAIN,
			                   "Would block sending SSH_FXP_STATUS");
		        return rc;
	        }
			else if(rc < 0) {
				_libssh2_error(session, LIBSSH2_ERROR_SOCKET_SEND,
				               "Unable to send SSH_FXP_VERSION");
			    goto sftp_status_error;
		    }
	        else {
				/* add up the number of bytes sent */
			    sftp->send_packet_sent += rc;

				// Still have more to send?
				if (sftp->send_packet_sent < sftp->send_packet_len)
					continue;

                /* Complete packet sent, move on */
				sftp->send_state = libssh2_NB_state_sent;
				break;
			}
		} while(1);
	}

	if (sftp->send_state == libssh2_NB_state_sent) {
//		LIBSSH2_FREE(session, sftp->send_packet);
//      sftp->send_packet = NULL;
		sftp->send_state = libssh2_NB_state_idle;
		return 0;
	}

sftp_status_error:
//    if (sftp->send_packet) {
//        LIBSSH2_FREE(session, sftp->send_packet);
//        sftp->send_packet = NULL;
//    }
    sftp->send_state = libssh2_NB_state_idle;
    return rc;
}

/*
 * libssh2_sftp_server_send_status
 *
 * Send SFTP status message.
 */
LIBSSH2_API int libssh2_sftp_server_send_status(LIBSSH2_SFTP *sftp, int error_code)
{
	int					rc = -1;
	LIBSSH2_SESSION*	session;
	LIBSSH2_CHANNEL*	channel;
	
    if(!sftp)
        return rc;
	channel = sftp->channel;
	session = channel->session;

    if(!(session->state & LIBSSH2_STATE_AUTHENTICATED)) {
        _libssh2_error(session, LIBSSH2_ERROR_INVAL,
                       "session not authenticated yet");
        return rc;
    }

    BLOCK_ADJUST(rc, session, sftp_send_status(sftp, error_code));
    return rc;
}

/*
 * libssh2_sftp_server_send_errno
 *
 * Convert errno to LIBSSH2 error code and send SFTP status message.
 */
LIBSSH2_API int libssh2_sftp_server_send_errno(LIBSSH2_SFTP *sftp, int error_code)
{
	int					rc = -1;
	LIBSSH2_SESSION*	session;
	LIBSSH2_CHANNEL*	channel;
	
    if(!sftp)
        return rc;
	channel = sftp->channel;
	session = channel->session;

    if(!(session->state & LIBSSH2_STATE_AUTHENTICATED)) {
        _libssh2_error(session, LIBSSH2_ERROR_INVAL,
                       "session not authenticated yet");
        return rc;
    }

    BLOCK_ADJUST(rc, session, sftp_send_status(sftp, sftp_diagnose_errno(error_code)));
    return rc;
}

/*
 * sftp_send_message
 *
 * Send SFTP message.
 */
static int sftp_send_message(LIBSSH2_SFTP *sftp, int msg_type,
							  char* data, int data_len)
{
	char*	s, sv;
	int					rc = -1;
	LIBSSH2_SESSION*	session;
	LIBSSH2_CHANNEL*	channel;
	
    if(!sftp)
        return rc;
	channel = sftp->channel;
	session = channel->session;

	if (sftp->send_state == libssh2_NB_state_idle) {
		switch(msg_type) {
			case SSH_FXP_EXTENDED_REPLY:
			case SSH_FXP_ATTRS:
			case SSH_FXP_NAME:
				// packet len(4) + message type(1) + request id(4) +
				// binary data(var)
				sftp->send_packet_len = 9 + data_len;
				s = sftp->send_packet = LIBSSH2_ALLOC(session, sftp->send_packet_len);
				_libssh2_store_u32(&s, sftp->send_packet_len - 4);
				*(s++) = msg_type;
				_libssh2_store_u32(&s, sftp->request_id);
				memcpy(s, data, data_len);
				break;
			// These cases all send just the msg_type, request_id and
			// the data length and binary data.
			case SSH_FXP_DATA:
			case SSH_FXP_HANDLE:
				// packet len(4) + message type(1) + request id(4) +
				// data len(4) + data(var)
				sftp->send_packet_len = 13 + data_len;
				s = sftp->send_packet = LIBSSH2_ALLOC(session, sftp->send_packet_len);
				_libssh2_store_u32(&s, sftp->send_packet_len - 4);
				*(s++) = msg_type;
				_libssh2_store_u32(&s, sftp->request_id);
				_libssh2_store_str(&s, data, data_len);
				break;
//			case SSH_FXP_EXTENDED:
//			case SSH_FXP_OPEN:
//			case SSH_FXP_CLOSE:
//			case SSH_FXP_READ:
//			case SSH_FXP_WRITE:
//			case SSH_FXP_LSTAT:
//			case SSH_FXP_FSTAT:
//			case SSH_FXP_SETSTAT:
//			case SSH_FXP_FSETSTAT:
//			case SSH_FXP_OPENDIR:
//			case SSH_FXP_READDIR:
//			case SSH_FXP_REMOVE:
//			case SSH_FXP_MKDIR:
//			case SSH_FXP_RMDIR:
//			case SSH_FXP_REALPATH:
//			case SSH_FXP_STAT:
//			case SSH_FXP_RENAME:
//			case SSH_FXP_READLINK:
//			case SSH_FXP_SYMLINK:
//			case SSH_FXP_STATUS:
			default:
				return -1;
				break; 
		}
	
		sftp->send_packet_sent = 0;
		sftp->send_state = libssh2_NB_state_created;
	}

	if (sftp->send_state == libssh2_NB_state_created) {
		do {
#ifdef LIBSSH2_TIMINGS
		time_in2 = (double)libssh2_clock();
#endif
//			rc = _libssh2_channel_write(channel, 0,
			rc = libssh2_channel_write_ex(channel, 0,
                                    (char *)sftp->send_packet +
                                    sftp->send_packet_sent,
                                    sftp->send_packet_len - sftp->send_packet_sent);
#ifdef LIBSSH2_TIMINGS
		time_out2 = (double)libssh2_clock();
		libssh2_channel_write_time += ((time_out2 - time_in2) / LIBSSH2_CLOCKS_PER_SEC);
#endif
			if (rc == LIBSSH2_ERROR_EAGAIN) {
				_libssh2_error(session, LIBSSH2_ERROR_EAGAIN,
                           "Would block sending SSH_FXP_STATUS");
	            return rc;
		    }
			else if(rc < 0) {
				_libssh2_error(session, LIBSSH2_ERROR_SOCKET_SEND,
                           "Unable to send SSH_FXP_VERSION");
	            goto sftp_message_error;
		    } else {
	            /* add up the number of bytes sent */
		        sftp->send_packet_sent += rc;

				// If more to send, send it.
				if (sftp->send_packet_sent < sftp->send_packet_len)
					continue;

				// Entire packet sent, move on.
				sftp->send_state = libssh2_NB_state_sent;
				break;
			}
		} while(1);
	}

	if (sftp->send_state == libssh2_NB_state_sent) {
		LIBSSH2_FREE(session, sftp->send_packet);
        sftp->send_packet = NULL;
		sftp->send_state = libssh2_NB_state_idle;
		return 0;
	}

sftp_message_error:
    if (sftp->send_packet) {
        LIBSSH2_FREE(session, sftp->send_packet);
        sftp->send_packet = NULL;
    }
    sftp->send_state = libssh2_NB_state_idle;
    return rc;
}

/*
 * libssh2_sftp_server_send_message
 *
 * Send SFTP message.
 */
LIBSSH2_API int libssh2_sftp_server_send_message(LIBSSH2_SFTP *sftp, int msg_type,
												  char* data, int data_len)
{
	int					rc = -1;
	
    if(!sftp)
        return rc;

    if(!(sftp->channel->session->state & LIBSSH2_STATE_AUTHENTICATED)) {
        _libssh2_error(sftp->channel->session, LIBSSH2_ERROR_INVAL,
                       "session not authenticated yet");
        return rc;
    }

    BLOCK_ADJUST(rc, sftp->channel->session, sftp_send_message(sftp, 
		msg_type, data, data_len));
    return rc;
}

/* *******************************
 * SFTP File and Directory Ops *
 ******************************* */

/* sftp_open
 */
static LIBSSH2_SFTP_HANDLE *
sftp_open(LIBSSH2_SFTP *sftp, const char *filename,
          size_t filename_len, size_t flags, const char* bin_attrs,
          int open_type)
{
	// The use of open_type has been changed. If 0, sftp_open will open a
	// directory. If non-zero, sftp_open will open a file. This was done
	// to allow open_type to contain a coded character set ID (CCSID).
	LIBSSH2_SFTP_HANDLE* handle;
	LIBSSH2_CHANNEL*	channel = sftp->channel;
    LIBSSH2_SESSION*	session = channel->session;
	LIBSSH2_SFTP_ATTRIBUTES attrs = {
        LIBSSH2_SFTP_ATTR_PERMISSIONS, 0, 0, 0, 0, 0, 0};
	unsigned char*	s;
    int				rc, retcode;
	int				oflags;
	int				read_only = 0;
	int				text_mode = 0;
	struct stat		sb;
	struct stat		file_sb;
	unsigned char	buffer[2048];
#ifdef __OS400__
	void			*rfile;
#endif

	if (sftp->open_state == libssh2_NB_state_idle) {
		handle = NULL;
		rc = 0;
		oflags = O_LARGEFILE;
		retcode = LIBSSH2_FX_OK;
		sftp->last_errno = 0;

		// Create SFTP Handle struct.
		handle = LIBSSH2_ALLOC(session, sizeof(LIBSSH2_SFTP_HANDLE));
		if (!handle) {
			sftp->last_errno = errno;
		    _libssh2_error(session, LIBSSH2_ERROR_ALLOC,
	                "Unable to allocate new SFTP handle structure");
			retcode = LIBSSH2_FX_FAILURE;
			goto sftp_open_error;
        }
	    memset(handle, 0, sizeof(LIBSSH2_SFTP_HANDLE));
		/* add this file handle to the list kept in the sftp session */
		_libssh2_list_add(&sftp->sftp_handles, &handle->node);
		memcpy(handle->filename, filename, filename_len);
		handle->handle_type = open_type ? LIBSSH2_SFTP_HANDLE_FILE :
	        LIBSSH2_SFTP_HANDLE_DIR;
		handle->sftp = sftp; /* point to the parent struct */
		handle->fd = -1;
		handle->u.file.offset = 0;
		handle->handle_len = 16;
        memcpy(handle->handle, (void*)&handle, handle->handle_len);
#ifdef __OS400__
		handle->ccsid = open_type;
		strcpy(handle->CRLF, lineEnd);
		handle->stream = fmtStream;
		handle->recsep = recordSep;
		handle->remove_blanks = trimBlanks;
		handle->truncate = truncateRecords;
		handle->format_records = formatRecords;
		memcpy(&handle->format_delimiter, formatDelim, 8);
		if (!memcmp(handle->filename, "/QSYS.LIB/", 10)) {
			// This is an AS/400 DBF file. Process it in record mode.
			handle->isDBF = 1;
		}
		if (handle->ccsid != 819 && handle->ccsid != 65535) {
			handle->translate = 1;
		}
#endif

		if (open_type) {
			libssh2_file_time = libssh2_network_time = 0;
			// convert attrs and flags.
			sftp_bin2attr(&attrs, bin_attrs);
			sftp_attr2stat(&attrs, &sb);
			if ((flags & (LIBSSH2_FXF_READ + LIBSSH2_FXF_WRITE)) ==
				LIBSSH2_FXF_READ + LIBSSH2_FXF_WRITE) {
				oflags |= O_RDWR;
			} else if (flags & LIBSSH2_FXF_READ) {
				oflags |= O_RDONLY;
				read_only = 1;
			} else if (flags & LIBSSH2_FXF_WRITE) {
				handle->write_mode = 1;
				oflags |= O_WRONLY;
			}
			if (flags & LIBSSH2_FXF_APPEND) {
				oflags |= O_APPEND;
				handle->append = 1;
			}
			if (flags & LIBSSH2_FXF_TRUNC) oflags |= O_TRUNC;
			if (flags & LIBSSH2_FXF_EXCL) oflags |= O_EXCL;
			if (flags & LIBSSH2_FXF_CREAT) oflags |= O_CREAT;
#ifdef __OS400__
			// If on an AS/400, open_type will contain the target CCS ID.
			oflags |= O_CCSID;
#if 0
			// Do a stat on the file. If it exists, set ccsid to the file
			// ccsid. Only do this for IFS files.
			if (handle->ccsid == 819) {
				if (stat(filename, &file_sb) == 0) {
					handle->ccsid = file_sb.st_ccsid;
				}
			}
			// If we are writing to non-ascii and non-binary, set up to 
			// open as text.
			if (!handle->stream && handle->ccsid != 819 && handle->ccsid != 65535) {
				oflags |= O_TEXTDATA;
				if (flags & LIBSSH2_FXF_CREAT) oflags |= O_TEXT_CREAT;
			}
#endif
			if (read_only) {
				if (handle->isDBF) {
					rc = sshDBFOpenRead(handle, handle->filename);
				} else {
//					handle->fd = open(handle->filename, oflags, sb.st_mode, 819);
					handle->fd = open(handle->filename, oflags, sb.st_mode, handle->ccsid);
				}
			} else {
				if (handle->isDBF) {
					rc = sshDBFOpenWrite(handle, handle->filename);
				} else {
//					handle->fd = open(handle->filename, oflags, sb.st_mode, handle->ccsid, 819);
					handle->fd = open(handle->filename, oflags, sb.st_mode, handle->ccsid);
				}
			}
#else
			handle->fd = open(handle->filename, oflags, sb.st_mode);
#endif

			if (handle->isDBF) {
				if (!handle->fileptr) {
					retcode = sftp_diagnose_errno(rc);
					sprintf(buffer, "Unable to open file %s: %s", filename,
					strerror(rc));
					_libssh2_error(session, LIBSSH2_ERROR_REQUEST_DENIED, buffer);
					goto sftp_open_error;
				}
			} else {
				if (handle->fd < 0) {
					sftp->last_errno = errno;
					retcode = sftp_diagnose_errno(errno);
					sprintf(buffer, "Unable to open file %s: %s", filename,
						strerror(errno));
					_libssh2_error(session, LIBSSH2_ERROR_REQUEST_DENIED, buffer);
					goto sftp_open_error;
				}
			}

		} else {
			if (!memcmp(handle->filename, "/QSYS.LIB/", 10)) {
				// This is an AS/400 DBF file. Process it in record mode.
				handle->isDBF = 1;
			}
			handle->fileptr = (void*)opendir(handle->filename);
			if (handle->fileptr == NULL) {
				sftp->last_errno = errno;
				retcode = sftp_diagnose_errno(errno);
				sprintf(buffer, "Unable to open directory %s: %s", filename,
					strerror(errno));
				_libssh2_error(session, LIBSSH2_ERROR_REQUEST_DENIED, buffer);
				goto sftp_open_error;
			}
		}

	    _libssh2_debug(session, LIBSSH2_TRACE_SFTP, "Open command successful");

		sftp->open_state = libssh2_NB_state_created;
	}

	if (sftp->open_state == libssh2_NB_state_created) {
		if (!handle) {
			rc = libssh2_sftp_server_send_status(sftp, retcode);
			if (rc == LIBSSH2_ERROR_EAGAIN) {
			   _libssh2_error(session, LIBSSH2_ERROR_EAGAIN,
                      "Would block sending SSH_FXP_STATUS");
				return NULL;
			}
			else if(rc < 0) {
				_libssh2_error(session, LIBSSH2_ERROR_SOCKET_SEND,
                          "Unable to send SSH_FXP_STATUS");
				retcode = LIBSSH2_FX_FAILURE;
				goto sftp_open_error2;
			}
		} else {
			rc = libssh2_sftp_server_send_message(sftp, SSH_FXP_HANDLE,
				handle->handle, handle->handle_len);
			if (rc == LIBSSH2_ERROR_EAGAIN) {
			   _libssh2_error(session, LIBSSH2_ERROR_EAGAIN,
                      "Would block sending SSH_FXP_HANDLE");
				return NULL;
			}
			else if(rc < 0) {
				_libssh2_error(session, LIBSSH2_ERROR_SOCKET_SEND,
                          "Unable to send SSH_FXP_HANDLE");
				retcode = LIBSSH2_FX_FAILURE;
				goto sftp_open_error2;
			}
			sftp->open_state = libssh2_NB_state_idle;
			return handle;
		}
	}

sftp_open_error:
	rc = libssh2_sftp_server_send_status(sftp, retcode);

sftp_open_error2:
	if (handle) {
		if (handle->fd > -1) close(handle->fd);
		if (handle->fileptr) {
			if (open_type) {
				rc = sshDBFClose(handle);
			} else {
				closedir(handle->fileptr);
			}
		}
		_libssh2_list_remove(&handle->node);
		LIBSSH2_FREE(session, handle);
	}

	sftp->open_state = libssh2_NB_state_idle;
	return NULL;
}

/* libssh2_sftp_server_opendir
 */
LIBSSH2_API LIBSSH2_SFTP_HANDLE *
libssh2_sftp_server_opendir(LIBSSH2_SFTP *sftp, const char *dirname,
                     unsigned int dirname_len)
{
    LIBSSH2_SFTP_HANDLE *hnd;

    if(!sftp)
        return NULL;

    BLOCK_ADJUST_ERRNO(hnd, sftp->channel->session,
                       sftp_open(sftp, dirname, dirname_len, 0, NULL,
					   0));
    return hnd;
}

/* libssh2_sftp_server_open
 */
LIBSSH2_API LIBSSH2_SFTP_HANDLE *
libssh2_sftp_server_open(LIBSSH2_SFTP *sftp, const char *filename,
                     unsigned int filename_len, size_t flags, const char* attrs,
					 int ccsid)
{
    LIBSSH2_SFTP_HANDLE *hnd;

    if(!sftp)
        return NULL;

    BLOCK_ADJUST_ERRNO(hnd, sftp->channel->session,
                       sftp_open(sftp, filename, filename_len, 
					   flags, attrs, ccsid));
    return hnd;
}

/* sftp_close_handle
 *
 * Close a file or directory handle
 * Also frees handle resource and unlinks it from the SFTP structure
 */
static int
sftp_close_handle(LIBSSH2_SFTP_HANDLE *handle)
{
    LIBSSH2_SFTP *sftp = handle->sftp;
    LIBSSH2_CHANNEL *channel = sftp->channel;
    LIBSSH2_SESSION *session = channel->session;
	void*		ptr;
    int retcode;
    int rc;
	unsigned char	buffer[2048];

    if (handle->close_state == libssh2_NB_state_idle) {
        _libssh2_debug(session, LIBSSH2_TRACE_SFTP, "Closing handle");
		rc = 0;
		retcode = LIBSSH2_FX_OK;
		sftp->last_errno = 0;

		if(handle->handle_type == LIBSSH2_SFTP_HANDLE_FILE) {
			if (handle->isDBF) {
				rc = sshDBFClose(handle);
			} else {
				rc = close(handle->fd);
				if (rc) rc = errno;
			}
		} else {
			rc = closedir((DIR*)handle->fileptr);
			if (rc) {
				sftp->last_errno = errno;
				rc = errno;
			}
		}
		if (rc) {
			retcode = sftp_diagnose_errno(rc);
			sprintf(buffer, "Error closing handle for %s: %s", handle->filename,
				strerror(rc));
			_libssh2_error(session, LIBSSH2_ERROR_REQUEST_DENIED, buffer);
		}

		handle->close_state = libssh2_NB_state_created;
	}

	if (handle->close_state == libssh2_NB_state_created) {
		rc = libssh2_sftp_server_send_status(sftp, retcode);
		if (rc == LIBSSH2_ERROR_EAGAIN) {
		   _libssh2_error(session, LIBSSH2_ERROR_EAGAIN,
                     "Would block sending SSH_FXP_STATUS");
			goto sftp_close_exit;
		}
		else if(rc < 0) {
			_libssh2_error(session, LIBSSH2_ERROR_SOCKET_SEND,
                         "Unable to send SSH_FXP_STATUS");
			goto sftp_close_exit;
		}

		handle->close_state = libssh2_NB_state_idle;
		goto sftp_close_exit;

	}

sftp_close_exit:
	handle->close_state = libssh2_NB_state_idle;
	if (handle->buffer) {
		LIBSSH2_FREE(session, handle->buffer);
		handle->buffer = NULL;
	}
	if (handle->file_buffer) {
		LIBSSH2_FREE(session, handle->file_buffer);
		handle->file_buffer = NULL;
	}
	_libssh2_list_remove(&handle->node);
	LIBSSH2_FREE(session, handle);
	return rc;
}

/* libssh2_sftp_close_handle
 *
 * Close a file or directory handle
 * Also frees handle resource and unlinks it from the SFTP structure
 */
LIBSSH2_API int
libssh2_sftp_server_close_handle(LIBSSH2_SFTP_HANDLE *hnd)
{
    int rc;
    if(!hnd)
        return LIBSSH2_ERROR_BAD_USE;
    BLOCK_ADJUST(rc, hnd->sftp->channel->session, sftp_close_handle(hnd));
    return rc;
}

/* sftp_stat
 * Stat or setstat a file or symbolic link
 */
static int sftp_stat(LIBSSH2_SFTP *sftp, const char *path,
                     unsigned int path_len, int stat_type,
                     unsigned char* bin_attrs)
{
    LIBSSH2_CHANNEL *channel = sftp->channel;
    LIBSSH2_SESSION *session = channel->session;
	LIBSSH2_SFTP_ATTRIBUTES attrs = {
        LIBSSH2_SFTP_ATTR_PERMISSIONS, 0, 0, 0, 0, 0, 0
    };
    unsigned char *s, *data;
    int rc, retcode;
	struct stat	sb;
	int				buflen;
	unsigned char	buffer[2048];

    if (sftp->stat_state == libssh2_NB_state_idle) {
		rc = 0;
		retcode = LIBSSH2_FX_OK;
		sftp->last_errno = 0;
        switch (stat_type) {
			case LIBSSH2_SFTP_SETSTAT:
				sftp_bin2attr(&attrs, bin_attrs);
				sftp_attr2stat(&attrs, &sb);
				if (chmod(path, sb.st_mode) < 0) {
					sftp->last_errno = errno;
					retcode = sftp_diagnose_errno(errno);
					sprintf(buffer, "Cannot setstat local file %s: %s",
						path, strerror(errno));
					_libssh2_error(session, LIBSSH2_ERROR_REQUEST_DENIED, buffer);
				}
				break;
			case LIBSSH2_SFTP_LSTAT:
				if (lstat(path, &sb) < 0) {
					sftp->last_errno = errno;
					retcode = sftp_diagnose_errno(errno);
					sprintf(buffer, "Cannot lstat local file %s: %s",
						path, strerror(errno));
					_libssh2_error(session, LIBSSH2_ERROR_REQUEST_DENIED, buffer);
				} else {
					if ((!memcmp(path, "/QSYS.LIB/", 10)) &&
						(!memcmp(path + (strlen(path) -  5), ".FILE", 5))) {
							sb.st_mode &= ~_S_IFDIR;
							sb.st_mode |= _S_IFREG;
					}
					sftp_stat2attr(&attrs, &sb);
				}
				break;
			case LIBSSH2_SFTP_STAT:
			default:
				if (stat(path, &sb) < 0) {
					sftp->last_errno = errno;
					retcode = sftp_diagnose_errno(errno);
					sprintf(buffer, "Cannot stat local file %s: %s",
						path, strerror(errno));
					_libssh2_error(session, LIBSSH2_ERROR_REQUEST_DENIED, buffer);
				} else {
					if ((!memcmp(path, "/QSYS.LIB/", 10)) &&
						(!memcmp(path + (strlen(path) -  5), ".FILE", 5))) {
							sb.st_mode &= ~_S_IFDIR;
							sb.st_mode |= _S_IFREG;
					}
					sftp_stat2attr(&attrs, &sb);
				}
				break;
		}
		sftp->stat_state = libssh2_NB_state_created;
	}

	if (sftp->stat_state == libssh2_NB_state_created) {
		if (retcode != LIBSSH2_FX_OK) {
			rc = libssh2_sftp_server_send_status(sftp,
					retcode);
			if (rc == LIBSSH2_ERROR_EAGAIN) {
			   _libssh2_error(session, LIBSSH2_ERROR_EAGAIN,
                      "Would block sending SSH_FXP_STATUS");
				return rc;
			}
			else if(rc < 0) {
				_libssh2_error(session, LIBSSH2_ERROR_SOCKET_SEND,
                          "Unable to send SSH_FXP_STATUS");
			}
		} else {
			switch (stat_type) {
				case LIBSSH2_SFTP_SETSTAT:
					break;
				case LIBSSH2_SFTP_LSTAT:
				case LIBSSH2_SFTP_STAT:
				default:
					buflen = sftp_attr2bin(buffer, &attrs);
					rc = libssh2_sftp_server_send_message(sftp, SSH_FXP_ATTRS, buffer, 
							buflen);
					if (rc == LIBSSH2_ERROR_EAGAIN) {
						_libssh2_error(session, LIBSSH2_ERROR_EAGAIN,
							"Would block sending SSH_FXP_ATTRS");
						return rc;
					}
					else if(rc < 0) {
						_libssh2_error(session, LIBSSH2_ERROR_SOCKET_SEND,
			                     "Unable to send SSH_FXP_ATTRS");
					}
					break;
			}
		}
		sftp->stat_state = libssh2_NB_state_idle;
		if (!retcode) return 0;
		return -1;
	}
}

/* libssh2_sftp_server_stat
 * Stat or setstat a file or symbolic link
 */
LIBSSH2_API int
libssh2_sftp_server_stat(LIBSSH2_SFTP *sftp, const char *path,
                     unsigned int path_len, int stat_type,
                     unsigned char* bin_attrs)
{
    int rc;
    if(!sftp)
        return LIBSSH2_ERROR_BAD_USE;
    BLOCK_ADJUST(rc, sftp->channel->session,
                 sftp_stat(sftp, path, path_len, stat_type, bin_attrs));
    return rc;
}

/* sftp_fstat
 * Stat or setstat a file or symbolic link by descriptor
 */
static int sftp_fstat(LIBSSH2_SFTP_HANDLE *handle, int stat_type,
                     unsigned char* bin_attrs)
{
    LIBSSH2_SFTP	*sftp = handle->sftp;
    LIBSSH2_CHANNEL	*channel = sftp->channel;
    LIBSSH2_SESSION *session = channel->session;
	LIBSSH2_SFTP_ATTRIBUTES attrs = {
        LIBSSH2_SFTP_ATTR_PERMISSIONS, 0, 0, 0, 0, 0, 0
    };
    unsigned char *s, *data;
    int rc, retcode;
	struct stat	sb;
	int				buflen;
	unsigned char	buffer[2048];

    if (sftp->fstat_state == libssh2_NB_state_idle) {
		rc = 0;
		retcode = LIBSSH2_FX_OK;
		sftp->last_errno = 0;
        switch (stat_type) {
			case LIBSSH2_SFTP_SETSTAT:
				retcode = LIBSSH2_FX_OP_UNSUPPORTED;
				sprintf(buffer, "Cannot fsetstat local file %s: %s",
					handle->filename, strerror(errno));
				_libssh2_error(session, LIBSSH2_ERROR_REQUEST_DENIED, buffer);
				break;
			case LIBSSH2_SFTP_STAT:
			default:
				if (fstat(handle->fd, &sb) < 0) {
					sftp->last_errno = errno;
					retcode = sftp_diagnose_errno(errno);
					sprintf(buffer, "Cannot fstat local file %s: %s",
						handle->filename, strerror(errno));
					_libssh2_error(session, LIBSSH2_ERROR_REQUEST_DENIED, buffer);
				} else {
					sftp_stat2attr(&attrs, &sb);
				}
				break;
		}
		sftp->fstat_state = libssh2_NB_state_created;
	}

	if (sftp->fstat_state == libssh2_NB_state_created) {
		if (retcode != LIBSSH2_FX_OK) {
			rc = libssh2_sftp_server_send_status(sftp,
					retcode);
			if (rc == LIBSSH2_ERROR_EAGAIN) {
			   _libssh2_error(session, LIBSSH2_ERROR_EAGAIN,
                      "Would block sending SSH_FXP_STATUS");
				return rc;
			}
			else if(rc < 0) {
				_libssh2_error(session, LIBSSH2_ERROR_SOCKET_SEND,
                          "Unable to send SSH_FXP_STATUS");
			}
		} else {
			switch (stat_type) {
				case LIBSSH2_SFTP_SETSTAT:
					break;
				case LIBSSH2_SFTP_STAT:
				default:
					buflen = sftp_attr2bin(buffer, &attrs);
					rc = libssh2_sftp_server_send_message(sftp, SSH_FXP_ATTRS, buffer, 
							buflen);
					if (rc == LIBSSH2_ERROR_EAGAIN) {
						_libssh2_error(session, LIBSSH2_ERROR_EAGAIN,
							"Would block sending SSH_FXP_ATTRS");
						return rc;
					}
					else if(rc < 0) {
						_libssh2_error(session, LIBSSH2_ERROR_SOCKET_SEND,
			                     "Unable to send SSH_FXP_ATTRS");
					}
					break;
			}
		}
		sftp->fstat_state = libssh2_NB_state_idle;
		if (!retcode) return 0;
		return -1;
	}
}

/* libssh2_sftp_server_fstat
 * Stat or setstat a file or symbolic link by descriptor.
 */
LIBSSH2_API int
libssh2_sftp_server_fstat(LIBSSH2_SFTP_HANDLE *hnd, int stat_type,
                     unsigned char* bin_attrs)
{
    int rc;
    if(!hnd)
        return LIBSSH2_ERROR_BAD_USE;
    BLOCK_ADJUST(rc, hnd->sftp->channel->session,
                 sftp_fstat(hnd, stat_type, bin_attrs));
    return rc;
}


/* sftp_unlink
 * Delete a file from the remote server
 */
static int sftp_unlink(LIBSSH2_SFTP *sftp, const char *filename,
                       unsigned int filename_len)
{
    LIBSSH2_CHANNEL *channel = sftp->channel;
    LIBSSH2_SESSION *session = channel->session;
    size_t data_len;
    int retcode;
    unsigned char *s, *data;
    int rc;
	unsigned char	buffer[2048];

    if (sftp->unlink_state == libssh2_NB_state_idle) {
		retcode = LIBSSH2_FX_OK;
		sftp->last_errno = 0;
		rc = unlink(filename);
		if (rc) {
			sftp->last_errno = errno;
			retcode = sftp_diagnose_errno(errno);
			sprintf(buffer, "Cannot unlink local file %s: %s",
				filename, strerror(errno));
			_libssh2_error(session, LIBSSH2_ERROR_REQUEST_DENIED, buffer);
		}
		sftp->unlink_state = libssh2_NB_state_created;
	}

    if (sftp->unlink_state == libssh2_NB_state_created) {
		rc = libssh2_sftp_server_send_status(sftp, retcode);
		if (rc == LIBSSH2_ERROR_EAGAIN) {
		   _libssh2_error(session, LIBSSH2_ERROR_EAGAIN,
                     "Would block sending SSH_FXP_STATUS");
			return rc;
		}
		else if(rc < 0) {
			_libssh2_error(session, LIBSSH2_ERROR_SOCKET_SEND,
                         "Unable to send SSH_FXP_STATUS");
		}
	}
	sftp->unlink_state = libssh2_NB_state_idle;
	return rc;
}

/* libssh2_sftp_server_unlink
 * Delete a file from the local server
 */
LIBSSH2_API int
libssh2_sftp_server_unlink(LIBSSH2_SFTP *sftp, const char *filename,
                       unsigned int filename_len)
{
    int rc;
    if(!sftp)
        return LIBSSH2_ERROR_BAD_USE;
    BLOCK_ADJUST(rc, sftp->channel->session,
                 sftp_unlink(sftp, filename, filename_len));
    return rc;
}

/*
 * sftp_mkdir
 *
 * Create an SFTP directory
 */
static int sftp_mkdir(LIBSSH2_SFTP *sftp, const char *path,
                 unsigned int path_len, unsigned char* bin_attrs)
{
    LIBSSH2_CHANNEL *channel = sftp->channel;
    LIBSSH2_SESSION *session = channel->session;
    LIBSSH2_SFTP_ATTRIBUTES attrs = {
        LIBSSH2_SFTP_ATTR_PERMISSIONS, 0, 0, 0, 0, 0, 0
    };
    size_t data_len;
    int retcode;
    unsigned char *packet, *s, *data;
    int rc;
	unsigned char	buffer[2048];

    if (sftp->mkdir_state == libssh2_NB_state_idle) {
		retcode = LIBSSH2_FX_OK;
		sftp->last_errno = 0;
		sftp_bin2attr(&attrs, bin_attrs);
		rc = mkdir(path, attrs.permissions);
		if (rc) {
			sftp->last_errno = errno;
			retcode = sftp_diagnose_errno(errno);
			sprintf(buffer, "Cannot make directory %s: %s",
				path, strerror(errno));
			_libssh2_error(session, LIBSSH2_ERROR_REQUEST_DENIED, buffer);
		}
		sftp->mkdir_state = libssh2_NB_state_created;
	}

	if (sftp->mkdir_state == libssh2_NB_state_created) {
		rc = libssh2_sftp_server_send_status(sftp, retcode);
		if (rc == LIBSSH2_ERROR_EAGAIN) {
		   _libssh2_error(session, LIBSSH2_ERROR_EAGAIN,
                     "Would block sending SSH_FXP_STATUS");
			return rc;
		}
		else if(rc < 0) {
			_libssh2_error(session, LIBSSH2_ERROR_SOCKET_SEND,
                         "Unable to send SSH_FXP_STATUS");
		}
	}
	sftp->mkdir_state = libssh2_NB_state_idle;
	return rc;
}

/*
 * libssh2_sftp_server_mkdir
 *
 * Create an SFTP directory
 */
LIBSSH2_API int
libssh2_sftp_server_mkdir(LIBSSH2_SFTP *sftp, const char *path,
                      unsigned int path_len, unsigned char* bin_attrs)
{
    int rc;
    if(!sftp)
        return LIBSSH2_ERROR_BAD_USE;
    BLOCK_ADJUST(rc, sftp->channel->session,
                 sftp_mkdir(sftp, path, path_len, bin_attrs));
    return rc;
}

/* sftp_rmdir
 * Remove a directory
 */
static int sftp_rmdir(LIBSSH2_SFTP *sftp, const char *path,
                      unsigned int path_len)
{
    LIBSSH2_CHANNEL *channel = sftp->channel;
    LIBSSH2_SESSION *session = channel->session;
    size_t data_len;
    int retcode;
    unsigned char *s, *data;
    int rc;
	unsigned char	buffer[2048];

    if (sftp->rmdir_state == libssh2_NB_state_idle) {
		retcode = LIBSSH2_FX_OK;
		sftp->last_errno = 0;
		rc = rmdir(path);
		if (rc) {
			sftp->last_errno = errno;
			retcode = sftp_diagnose_errno(errno);
			sprintf(buffer, "Cannot remove directory %s: %s",
				path, strerror(errno));
			_libssh2_error(session, LIBSSH2_ERROR_REQUEST_DENIED, buffer);
		}
		sftp->rmdir_state = libssh2_NB_state_created;
	}

	if (sftp->rmdir_state == libssh2_NB_state_created) {
		rc = libssh2_sftp_server_send_status(sftp, retcode);
		if (rc == LIBSSH2_ERROR_EAGAIN) {
		   _libssh2_error(session, LIBSSH2_ERROR_EAGAIN,
                     "Would block sending SSH_FXP_STATUS");
			return rc;
		}
		else if(rc < 0) {
			_libssh2_error(session, LIBSSH2_ERROR_SOCKET_SEND,
                         "Unable to send SSH_FXP_STATUS");
		}
	}
	sftp->rmdir_state = libssh2_NB_state_idle;
	return rc;
}

/* libssh2_sftp_server_rmdir
 * Remove a directory
 */
LIBSSH2_API int
libssh2_sftp_server_rmdir(LIBSSH2_SFTP *sftp, const char *path,
                      unsigned int path_len)
{
    int rc;
    if(!sftp)
        return LIBSSH2_ERROR_BAD_USE;
    BLOCK_ADJUST(rc, sftp->channel->session,
                 sftp_rmdir(sftp, path, path_len));
    return rc;
}

/*
 * sftp_rename
 *
 * Rename a file on the remote server
 */
static int sftp_rename(LIBSSH2_SFTP *sftp, const char *source_filename,
                       unsigned int source_filename_len,
                       const char *dest_filename,
                       unsigned int dest_filename_len, long flags)
{
    LIBSSH2_CHANNEL *channel = sftp->channel;
    LIBSSH2_SESSION *session = channel->session;
    size_t			data_len;
    unsigned char*	data;
	int				rc, retcode;
	unsigned char	buffer[2048];

    if (sftp->version < 2) {
        return _libssh2_error(session, LIBSSH2_ERROR_SFTP_PROTOCOL,
                              "Server does not support RENAME");
    }

   if (sftp->rename_state == libssh2_NB_state_idle) {
	   retcode = LIBSSH2_FX_OK;
	   sftp->last_errno = 0;
	   if (sftp->version < 2) {
		   retcode = LIBSSH2_FX_OP_UNSUPPORTED;
		   _libssh2_error(session, LIBSSH2_ERROR_SFTP_PROTOCOL,
			   "Server does not support RENAME");
	   } else {
		   rc = rename(source_filename, dest_filename);
		   if (rc) {
			   sftp->last_errno = errno;
			   retcode = sftp_diagnose_errno(errno);
			   sprintf(buffer, "Cannot rename file %s: %s",
				   source_filename, strerror(errno));
			   _libssh2_error(session, LIBSSH2_ERROR_REQUEST_DENIED, buffer);
		   }
	   }
	   sftp->rename_state = libssh2_NB_state_created;
   }

   if (sftp->rename_state == libssh2_NB_state_created) {
	   rc = libssh2_sftp_server_send_status(sftp, retcode);
	   if (rc == LIBSSH2_ERROR_EAGAIN) {
		   _libssh2_error(session, LIBSSH2_ERROR_EAGAIN,
			   "Would block sending SSH_FXP_STATUS");
		   return rc;
	   }
	   else if(rc < 0) {
		   _libssh2_error(session, LIBSSH2_ERROR_SOCKET_SEND,
			   "Unable to send SSH_FXP_STATUS");
	   }
   }

	sftp->rename_state = libssh2_NB_state_idle;
	return rc;
}

/* libssh2_sftp_server_rename
 * Rename a file on the local server
 */
LIBSSH2_API int
libssh2_sftp_server_rename(LIBSSH2_SFTP *sftp, const char *source_filename,
                       unsigned int source_filename_len,
                       const char *dest_filename,
                       unsigned int dest_filename_len, long flags)
{
    int rc;
    if(!sftp)
        return LIBSSH2_ERROR_BAD_USE;
    BLOCK_ADJUST(rc, sftp->channel->session,
                 sftp_rename(sftp, source_filename, source_filename_len,
                             dest_filename, dest_filename_len, flags));
    return rc;
}

/* sftp_readdir
 * Read from an SFTP directory handle
 */
static int sftp_readdir(LIBSSH2_SFTP_HANDLE *handle)
{
    LIBSSH2_SFTP *sftp = handle->sftp;
    LIBSSH2_CHANNEL *channel = sftp->channel;
    LIBSSH2_SESSION *session = channel->session;
	LIBSSH2_SFTP_ATTRIBUTES		file_attrs;
    size_t data_len, filename_len, num_names;
    unsigned char *s, *p, *l, *data, *cp;
    int rc, retcode, x;
	size_t	packet_len;
	struct dirent	entry;
	struct dirent*	result;
	struct stat	sb;
	unsigned char	filename[512];
	unsigned char	buffer[2048];
	unsigned char*	bufptr = buffer;

    if (sftp->readdir_state == libssh2_NB_state_idle) {
		num_names = 0;
		retcode = LIBSSH2_FX_OK;
		sftp->last_errno = 0;
		packet_len = channel->remote.packet_size;		// Maximum packet size.
		data_len = 0;									// Number of byts in packet.
		if (handle->handle_type != LIBSSH2_SFTP_HANDLE_DIR) {
			retcode = LIBSSH2_FX_INVALID_HANDLE;
			_libssh2_error(session, LIBSSH2_ERROR_INVAL,
				"Invalid SFTP_HANDLE used for readdir");
			rc = -101;
			goto sftp_readdir_error;
		}
		s = sftp->readdir_packet = LIBSSH2_ALLOC(session, packet_len);
		if (!sftp->readdir_packet) {
			_libssh2_error(session, LIBSSH2_ERROR_ALLOC,
				"Unable to allocate readdir packet");
			retcode = LIBSSH2_FX_FAILURE;
			rc = -102;
			goto sftp_readdir_error;
		}
		s += 4;		// Skip spot for number of names.
		rc = 0;

		for( rc = readdir_r((DIR*)handle->fileptr, &entry, &result);
				result != NULL && rc == 0;
				rc = readdir_r((DIR*)handle->fileptr, &entry, &result)) {
			sprintf(buffer, "%s/%s", handle->filename, entry.d_name);
			if (stat(buffer, &sb) < 0) {
				retcode = sftp_diagnose_errno(errno);
				sprintf(buffer, "Cannot stat local file %s: %s",
					handle->filename, strerror(errno));
				_libssh2_error(session, LIBSSH2_ERROR_REQUEST_DENIED, buffer);
				rc = -103;
				goto sftp_readdir_error;
			} else {
				sftp_stat2attr(&file_attrs, &sb);
			}
			if ((!S_ISDIR(sb.st_mode)) && (!S_ISREG(sb.st_mode)) &&
				(!S_ISLNK(sb.st_mode))) {
				// Not a directory, regular file or symbolic link, skip it.
				continue;
			}
			num_names++;
			memset(filename, 0, sizeof(filename));
			filename_len = entry.d_namelen;
			memcpy(filename, entry.d_name, filename_len);
			if (handle->isDBF) {
				// If we're listing a DBF directory, files look like directories.
				// We have to change them to look like files and remove the .FILE
				// extensions from them.
				cp = strstr(filename, ".FILE");
				if (cp) {
					*cp = 0;		// Remove the .FILE extension.
					filename_len = strlen(filename);
					sb.st_mode &= 0xff - _S_IFDIR;
					sb.st_mode |= _S_IFREG;
					sftp_stat2attr(&file_attrs, &sb);
				}
			}
			_libssh2_store_text(&s, filename, filename_len);
			// build longentry.
			sftp_make_longentry(filename, filename_len, &sb);
			_libssh2_store_text(&s, longentry, strlen(longentry));
			s += sftp_attr2bin(s, &file_attrs);
			data_len = s - sftp->readdir_packet;
			if (packet_len - data_len < 2048) break;
		}
		if (rc < 0) {
			sftp->last_errno = errno;
			goto sftp_readdir_error;
		}
		if (num_names == 0) {
			retcode = LIBSSH2_FX_EOF;
			goto sftp_readdir_error;
		}
		p = sftp->readdir_packet;
		_libssh2_store_u32(&p, num_names);
		if (!num_names) data_len = 4;
		sftp->readdir_state = libssh2_NB_state_created;
	}

	if (sftp->readdir_state == libssh2_NB_state_created) {
		if (retcode) goto sftp_readdir_error;
		rc = libssh2_sftp_server_send_message(sftp, SSH_FXP_NAME, 
			sftp->readdir_packet, data_len);
		if (rc == LIBSSH2_ERROR_EAGAIN) {
			_libssh2_error(session, LIBSSH2_ERROR_EAGAIN,
				"Would block sending SSH_FXP_NAME");
			return rc;
		} else if(rc < 0) {
			_libssh2_error(session, LIBSSH2_ERROR_SOCKET_SEND,
				"Unable to send SSH_FXP_NAME");
			goto sftp_readdir_error;
		}
		LIBSSH2_FREE(session, sftp->readdir_packet);
		sftp->readdir_packet = NULL;
		sftp->readdir_state = libssh2_NB_state_idle;
		return 0;
	}

sftp_readdir_error:
	sftp->readdir_state = libssh2_NB_state_idle;
	libssh2_sftp_server_send_status(sftp, retcode);
	if (sftp->readdir_packet) {
		LIBSSH2_FREE(session, sftp->readdir_packet);
		sftp->readdir_packet = NULL;
	}
	return rc;
}

/* libssh2_sftp_server_readdir
 * Read from an SFTP directory handle and send results to client.
 */
LIBSSH2_API int
libssh2_sftp_server_readdir(LIBSSH2_SFTP_HANDLE *hnd)
{
    int rc;
    if(!hnd)
        return LIBSSH2_ERROR_BAD_USE;
    BLOCK_ADJUST(rc, hnd->sftp->channel->session, sftp_readdir(hnd));
    return rc;
}

/* sftp_read
 * Read from an SFTP file handle
 */
static int sftp_read(LIBSSH2_SFTP_HANDLE * handle, libssh2_uint64_t offset,
                         size_t bytes_requested)
{
    LIBSSH2_SFTP *sftp = handle->sftp;
    LIBSSH2_CHANNEL *channel = sftp->channel;
    LIBSSH2_SESSION *session = channel->session;
    unsigned char *packet, *s, *cp;
    int retcode, rc, lineLen, x;
	ssize_t bytes_read;
	ssize_t bytes_to_read;
	unsigned char	buffer[65000];

	if (sftp->read_state == libssh2_NB_state_idle) {
		retcode = LIBSSH2_FX_OK;
		sftp->last_errno = 0;
		rc = 0;
#ifdef LIBSSH2_TIMINGS
		time_in = (double)libssh2_clock();
#endif

		if (!handle->isDBF && handle->u.file.offset != offset) {
			if ((handle->u.file.offset = lseek64(handle->fd, offset, SEEK_SET)) < 0) {
				retcode = sftp_diagnose_errno(errno);
				sprintf(buffer, "Cannot seek within local file %s: %s",
						handle->filename, strerror(errno));
				_libssh2_error(session, LIBSSH2_ERROR_REQUEST_DENIED, buffer);
				rc = -100;
				goto sftp_read_error;
			}
		}

		if (handle->eof) {
			retcode = LIBSSH2_FX_EOF;
			rc = -101;
			goto sftp_read_error;
		}

		if (!handle->buffer) {
			if ((handle->buffer = LIBSSH2_ALLOC(session, 65000)) == NULL) {
				_libssh2_error(session, LIBSSH2_ERROR_ALLOC,
					"Unable to allocate read buffer");
				retcode = LIBSSH2_FX_FAILURE;
				rc = -102;
				goto sftp_read_error;
			}
		}

		bytes_to_read = sizeof(buffer);
		if (bytes_requested < bytes_to_read) bytes_to_read = bytes_requested;
		handle->bytes_to_send = 0;
		bytes_read = 0;

		do {
#ifdef LIBSSH2_TIMINGS
			time_in2 = (double)libssh2_clock();
#endif
			if (handle->isDBF) {
//				bytes_read = sshDBFRead(handle, buffer,	bytes_to_read);
				bytes_read = sshDBFRead(handle, handle->buffer + handle->bytes_to_send,
					bytes_to_read);
			} else {
//				bytes_read = read(handle->fd, buffer, bytes_to_read);
				bytes_read = read(handle->fd, handle->buffer + handle->bytes_to_send,
					bytes_to_read);
				if (bytes_read > 0) handle->bytes_in_file += bytes_read;
				if (bytes_read < 0) sftp->last_errno = errno;
			}
#ifdef LIBSSH2_TIMINGS
		time_out2 = (double)libssh2_clock();
		libssh2_file_read += ((time_out2 - time_in2) / LIBSSH2_CLOCKS_PER_SEC);
#endif
			if (bytes_read < bytes_to_read) {
				retcode = 0;
			}
			if (bytes_read <= 0) {
				if (bytes_read == 0) {
					handle->eof = 1;
					if (handle->bytes_to_send) break;
					retcode = LIBSSH2_FX_EOF;
					rc = -103;
					goto sftp_read_error;
				} else {
					retcode = sftp_diagnose_errno(sftp->last_errno);
					if (!retcode) retcode = LIBSSH2_FX_FAILURE;
					sprintf(buffer, "Cannot read local file %s: %s",
						handle->filename, strerror(sftp->last_errno));
					_libssh2_error(session, LIBSSH2_ERROR_REQUEST_DENIED, buffer);
					rc = retcode;
					goto sftp_read_error;
				}
			}
#ifdef EBCDIC
			// Allow for translation of EBCDIC data to ASCII (819) if IFS.
			if (!handle->isDBF && handle->translate) {
//				libssh2_make_ascii(buffer, bytes_read);
				libssh2_make_ascii(handle->buffer + handle->bytes_to_send, bytes_read);
			}
#endif
//			buffer[bytes_read] = 0x00;
//			memcpy(handle->buffer + handle->bytes_to_send, buffer, bytes_read);
			handle->bytes_to_send += bytes_read;
			bytes_read = 0;
			bytes_to_read = bytes_requested - handle->bytes_to_send;
		} while(handle->bytes_to_send < bytes_requested);

		if (handle->bytes_to_send < bytes_requested) handle->eof = 1;
		handle->u.file.offset += handle->bytes_to_send;
#ifdef LIBSSH2_TIMINGS
		time_out = (double)libssh2_clock();
		libssh2_file_time += ((time_out - time_in) / LIBSSH2_CLOCKS_PER_SEC);
		time_in = time_out;
#endif
		sftp->read_state = libssh2_NB_state_created;
	}

	if (sftp->read_state == libssh2_NB_state_created) {
		rc = libssh2_sftp_server_send_message(sftp, SSH_FXP_DATA, 
			handle->buffer, handle->bytes_to_send);
		if (rc == LIBSSH2_ERROR_EAGAIN) {
			_libssh2_error(session, LIBSSH2_ERROR_EAGAIN,
				"Would block sending SSH_FXP_DATA");
			return rc;
		} else if(rc < 0) {
			_libssh2_error(session, LIBSSH2_ERROR_SOCKET_SEND,
				"Unable to send SSH_FXP_DATA");
			retcode = LIBSSH2_FX_FAILURE;
			goto sftp_read_error;
		}
//		LIBSSH2_FREE(session, handle->buffer);
//		handle->buffer = NULL;
#ifdef LIBSSH2_TIMINGS
		time_out = (double)libssh2_clock();
		libssh2_network_time += ((time_out - time_in) / LIBSSH2_CLOCKS_PER_SEC);
#endif
		sftp->read_state = libssh2_NB_state_idle;
		return 0;
	}

sftp_read_error:
	sftp->read_state = libssh2_NB_state_idle;
	libssh2_sftp_server_send_status(sftp, retcode);
	if (handle->buffer) {
//		LIBSSH2_FREE(session, handle->buffer);
//		handle->buffer = NULL;
	}
	if (retcode == LIBSSH2_FX_EOF) return 0;
	return rc;
}

/* libssh2_sftp_server_read
 * Read from an SFTP file handle and send data to client.
 */
LIBSSH2_API int
libssh2_sftp_server_read(LIBSSH2_SFTP_HANDLE *hnd, libssh2_uint64_t offset,
						 size_t bytes_requested)
{
    int rc;
    if(!hnd)
        return LIBSSH2_ERROR_BAD_USE;
    BLOCK_ADJUST(rc, hnd->sftp->channel->session, sftp_read(hnd,
		offset, bytes_requested));
    return rc;
}

/*
 * sftp_write
 *
 * Write data to an SFTP handle. Returns the number of bytes written, or
 * a negative error code.
 */
static int sftp_write(LIBSSH2_SFTP_HANDLE *handle, libssh2_uint64_t offset,
						  const char *data, size_t data_len)
{
    LIBSSH2_SFTP	*sftp = handle->sftp;
    LIBSSH2_CHANNEL *channel = sftp->channel;
    LIBSSH2_SESSION *session = channel->session;
	ssize_t			written, bytes_written, bytes_remaining;
	ssize_t			bytes_to_write;
    int				rc, retcode;
	int				from, to;
	unsigned char	buffer[2048];
	char			*bufPtr;
	unsigned char	xlate_buf[32768];

	if (sftp->write_state == libssh2_NB_state_idle) {
		retcode = LIBSSH2_FX_OK;
		sftp->last_errno = 0;
		bytes_remaining = data_len;
		bytes_written = 0;
#ifdef LIBSSH2_TIMINGS
		time_in = (double)libssh2_clock();
#endif

		if (handle->u.file.offset != offset) {
			if ((handle->u.file.offset = lseek64(handle->fd, offset, SEEK_SET)) < 0) {
				sftp->last_errno = errno;
				retcode = sftp_diagnose_errno(errno);
				sprintf(buffer, "Cannot seek within local file %s: %s",
						handle->filename, strerror(errno));
				_libssh2_error(session, LIBSSH2_ERROR_REQUEST_DENIED, buffer);
			}
		}

		bufPtr = (char*)data;

#if EBCDIC
		if (handle->translate) libssh2_make_ebcdic((unsigned char*)data, data_len);
#endif

		if (retcode == LIBSSH2_FX_OK) {
			do {
				bytes_to_write = bytes_remaining;
				if (bytes_to_write > INT_MAX) bytes_to_write = INT_MAX;
#ifdef LIBSSH2_TIMINGS
		time_in2 = (double)libssh2_clock();
#endif
				if (handle->isDBF) {
					written = sshDBFWrite(handle, bufPtr, bytes_to_write);
				} else {
					written = write(handle->fd, bufPtr + bytes_written,
						bytes_to_write);
					handle->bytes_in_file += bytes_to_write;
					if (written < 0) sftp->last_errno = errno;
				}
#ifdef LIBSSH2_TIMINGS
		time_out2 = (double)libssh2_clock();
		libssh2_file_write += ((time_out2 - time_in2) / LIBSSH2_CLOCKS_PER_SEC);
#endif
				if (written < 0) {
					retcode = sftp_diagnose_errno(sftp->last_errno);
					if (retcode == 0) retcode = LIBSSH2_FX_FAILURE;
					sprintf(buffer, "Cannot write local file %s: %s",
							handle->filename, strerror(sftp->last_errno));
					_libssh2_error(session, LIBSSH2_ERROR_REQUEST_DENIED, buffer);
					break;
				}
				bytes_written += written;
				bytes_remaining -= written;
			} while(bytes_remaining);
			handle->u.file.offset += data_len;
		}
#ifdef LIBSSH2_TIMINGS
		time_out = (double)libssh2_clock();
		libssh2_file_time += ((time_out - time_in) / LIBSSH2_CLOCKS_PER_SEC);
		time_in = time_out;
#endif
		sftp->write_state = libssh2_NB_state_created;
	}

	if (sftp->write_state == libssh2_NB_state_created) {
		rc = libssh2_sftp_server_send_status(sftp, retcode);
		if (rc == LIBSSH2_ERROR_EAGAIN) {
			_libssh2_error(session, LIBSSH2_ERROR_EAGAIN,
				"Would block sending SSH_FXP_STATUS");
			return rc;
		} else if(rc < 0) {
			_libssh2_error(session, LIBSSH2_ERROR_SOCKET_SEND,
				"Unable to send SSH_FXP_STATUS");
		}
#ifdef LIBSSH2_TIMINGS
		time_out = (double)libssh2_clock();
		libssh2_network_time += ((time_out - time_in) / LIBSSH2_CLOCKS_PER_SEC);
#endif
		sftp->write_state = libssh2_NB_state_idle;
		if (!retcode) return 0;
		return -1;
	}
}

/* libssh2_sftp_server_write
 * Write to an SFTP file handle using data from client.
 */
LIBSSH2_API int
libssh2_sftp_server_write(LIBSSH2_SFTP_HANDLE *hnd, libssh2_uint64_t offset,
						 const char *buffer, size_t count)
{
    int rc;
    if(!hnd)
        return LIBSSH2_ERROR_BAD_USE;
    BLOCK_ADJUST(rc, hnd->sftp->channel->session, sftp_write(hnd, offset,
		buffer, count));
    return rc;
}

/*
 * sftp_fstatvfs
 *
 * SSH2 extended command. Get file system info for a descriptor and send to client.
 */
static int sftp_fstatvfs(LIBSSH2_SFTP_HANDLE *handle)
{
    LIBSSH2_SFTP	*sftp = handle->sftp;
    LIBSSH2_CHANNEL *channel = sftp->channel;
    LIBSSH2_SESSION *session = channel->session;
    int				rc, retcode, data_len;
	unsigned long	flags;
	struct statvfs64	info;
	unsigned char*	s;
	unsigned char	buffer[2048];

	if (sftp->fstatvfs_state == libssh2_NB_state_idle) {
		retcode = LIBSSH2_FX_OK;
		sftp->last_errno = 0;

		if (fstatvfs64(handle->fd, &info)) {
			sftp->last_errno = errno;
			retcode = sftp_diagnose_errno(errno);
			sprintf(buffer, "SSH2: fstatvfs failed for %s: %s", handle->filename,
				strerror(errno));
			_libssh2_error(session, LIBSSH2_ERROR_REQUEST_DENIED, buffer);
		}

		if (!retcode) {
			flags = 0;
			flags = (info.f_bsize & ST_RDONLY) ? SSH_FXE_STATVFS_ST_RDONLY : 0;
			flags |= (info.f_bsize & ST_NOSUID) ? SSH_FXE_STATVFS_ST_NOSUID : 0;
			s = buffer;
			_libssh2_store_u64(&s, info.f_bsize);
			_libssh2_store_u64(&s, info.f_frsize);
			_libssh2_store_u64(&s, info.f_blocks);
			_libssh2_store_u64(&s, info.f_bfree);
			_libssh2_store_u64(&s, info.f_bavail);
			_libssh2_store_u64(&s, info.f_files);
			_libssh2_store_u64(&s, info.f_ffree);
			_libssh2_store_u64(&s, info.f_favail);
			_libssh2_store_u64(&s, info.f_fsid);
			_libssh2_store_u64(&s, flags);
			_libssh2_store_u64(&s, info.f_namemax);
			data_len = s - buffer;
		}

		sftp->fstatvfs_state = libssh2_NB_state_created;
	}

	if (sftp->fstatvfs_state == libssh2_NB_state_created) {
		if (retcode != LIBSSH2_FX_OK) {
			rc = libssh2_sftp_server_send_status(sftp,
					retcode);
			if (rc == LIBSSH2_ERROR_EAGAIN) {
			   _libssh2_error(session, LIBSSH2_ERROR_EAGAIN,
                      "Would block sending SSH_FXP_STATUS");
				return rc;
			}
			else if(rc < 0) {
				_libssh2_error(session, LIBSSH2_ERROR_SOCKET_SEND,
                          "Unable to send SSH_FXP_STATUS");
			}
		} else {
			libssh2_sftp_server_send_message(sftp, SSH_FXP_EXTENDED_REPLY, 
				buffer, data_len);
			if (rc == LIBSSH2_ERROR_EAGAIN) {
				_libssh2_error(session, LIBSSH2_ERROR_EAGAIN,
					"Would block sending SSH_FXP_EXTENDED_REPLY");
				return rc;
			} else if(rc < 0) {
				_libssh2_error(session, LIBSSH2_ERROR_SOCKET_SEND,
					"Unable to send SSH_FXP_EXTENDED_REPLY");
			}
		}
		sftp->fstatvfs_state = libssh2_NB_state_idle;
		if (!retcode) return 0;
		return -1;
	}
}

/* libssh2_sftp_server_fstatvfs
 * SSH2 extended command. Get file system info for a descriptor and send to client.
 */
LIBSSH2_API int
libssh2_sftp_server_fstatvfs(LIBSSH2_SFTP_HANDLE *hnd)
{
    int rc;
    if(!hnd)
        return LIBSSH2_ERROR_BAD_USE;
    BLOCK_ADJUST(rc, hnd->sftp->channel->session, sftp_fstatvfs(hnd));
    return rc;
}

/*
 * sftp_statvfs
 *
 * SSH2 extended command. Get file system info for a file and send to client.
 */
static int sftp_statvfs(LIBSSH2_SFTP *sftp, unsigned char* path, int path_len)
{
    LIBSSH2_CHANNEL *channel = sftp->channel;
    LIBSSH2_SESSION *session = channel->session;
    int				rc, retcode, data_len;
	unsigned long	flags;
	struct statvfs64	info;
	unsigned char*	s;
	unsigned char	buffer[2048];

	if (sftp->statvfs_state == libssh2_NB_state_idle) {
		retcode = LIBSSH2_FX_OK;
		sftp->last_errno = 0;

		if (statvfs64(path, &info)) {
			sftp->last_errno = errno;
			retcode = sftp_diagnose_errno(errno);
			sprintf(buffer, "SSH2: fstatvfs failed for %s: %s", path,
				strerror(errno));
			_libssh2_error(session, LIBSSH2_ERROR_REQUEST_DENIED, buffer);
		}

		if (!retcode) {
			flags = 0;
			flags = (info.f_bsize & ST_RDONLY) ? SSH_FXE_STATVFS_ST_RDONLY : 0;
			flags |= (info.f_bsize & ST_NOSUID) ? SSH_FXE_STATVFS_ST_NOSUID : 0;
			s = buffer;
			_libssh2_store_u64(&s, info.f_bsize);
			_libssh2_store_u64(&s, info.f_frsize);
			_libssh2_store_u64(&s, info.f_blocks);
			_libssh2_store_u64(&s, info.f_bfree);
			_libssh2_store_u64(&s, info.f_bavail);
			_libssh2_store_u64(&s, info.f_files);
			_libssh2_store_u64(&s, info.f_ffree);
			_libssh2_store_u64(&s, info.f_favail);
			_libssh2_store_u64(&s, info.f_fsid);
			_libssh2_store_u64(&s, flags);
			_libssh2_store_u64(&s, info.f_namemax);
			data_len = s - buffer;
		}

		sftp->statvfs_state = libssh2_NB_state_created;
	}

	if (sftp->statvfs_state == libssh2_NB_state_created) {
		if (retcode != LIBSSH2_FX_OK) {
			rc = libssh2_sftp_server_send_status(sftp,
					retcode);
			if (rc == LIBSSH2_ERROR_EAGAIN) {
			   _libssh2_error(session, LIBSSH2_ERROR_EAGAIN,
                      "Would block sending SSH_FXP_STATUS");
				return rc;
			}
			else if(rc < 0) {
				_libssh2_error(session, LIBSSH2_ERROR_SOCKET_SEND,
                          "Unable to send SSH_FXP_STATUS");
			}
		} else {
			libssh2_sftp_server_send_message(sftp, SSH_FXP_EXTENDED_REPLY, 
				buffer, data_len);
			if (rc == LIBSSH2_ERROR_EAGAIN) {
				_libssh2_error(session, LIBSSH2_ERROR_EAGAIN,
					"Would block sending SSH_FXP_EXTENDED_REPLY");
				return rc;
			} else if(rc < 0) {
				_libssh2_error(session, LIBSSH2_ERROR_SOCKET_SEND,
					"Unable to send SSH_FXP_EXTENDED_REPLY");
			}
		}
		sftp->statvfs_state = libssh2_NB_state_idle;
		if (!retcode) return 0;
		return -1;
	}
}

/* libssh2_sftp_server_statvfs
 * SSH2 extended command. Get file system info for a descriptor and send to client.
 */
LIBSSH2_API int
libssh2_sftp_server_statvfs(LIBSSH2_SFTP *sftp, unsigned char* path, int path_len)
{
    int rc;
    if(!sftp)
        return LIBSSH2_ERROR_BAD_USE;
    BLOCK_ADJUST(rc, sftp->channel->session, sftp_statvfs(sftp, path, path_len));
    return rc;
}


/* sftp_realpath
 * Return real path for pathname to client.
 */
static int sftp_realpath(LIBSSH2_SFTP *sftp, const char *path,
                        unsigned int path_len)
{
	LIBSSH2_CHANNEL *channel = sftp->channel;
    LIBSSH2_SESSION *session = channel->session;
	LIBSSH2_SFTP_ATTRIBUTES attrs = {
        LIBSSH2_SFTP_ATTR_PERMISSIONS, 0, 0, 0, 0, 0, 0
    };
	struct stat	sb;
    size_t data_len;
    int retcode;
    unsigned char *data, *s;
	int rc;
	unsigned char	buffer[1024];
	unsigned char	real_filename[1024];
	int				real_length;

	if (sftp->stat_state == libssh2_NB_state_idle) {
		retcode = LIBSSH2_FX_OK;
		sftp->last_errno = 0;
		memset(real_filename, 0, sizeof(real_filename));
		if (path[0] == '/') {
			memcpy(real_filename, path, path_len);
		} else if ((strlen(path) == 1) && path[0] == '.') {
			if (getcwd(real_filename, sizeof(real_filename)) == NULL) {
				sftp->last_errno = errno;
				retcode = sftp_diagnose_errno(errno);
				fprintf (stderr, "SSHD: getcwd() error, rc=%i, errno=%i\n",
					rc, errno);
				libssh2_sftp_server_send_status(sftp, 
					LIBSSH2_FX_INVALID_FILENAME);
			}
		} else {
			if ((rc = readlink(path, real_filename, sizeof(real_filename))) < 0) {
				sftp->last_errno = errno;
				retcode = sftp_diagnose_errno(errno);
				fprintf (stderr, "SSHD: readlink() error, rc=%i, errno=%i\n",
					rc, errno);
				libssh2_sftp_server_send_status(sftp, 
					LIBSSH2_FX_INVALID_FILENAME);
			}
		}
		if (stat(real_filename, &sb) < 0) {
			sftp->last_errno = errno;
			retcode = sftp_diagnose_errno(errno);
			sprintf(buffer, "Cannot stat local file %s: %s",
				real_filename, strerror(errno));
			_libssh2_error(session, LIBSSH2_ERROR_REQUEST_DENIED, buffer);
			return -1;
		}
		memset(buf, 0, sizeof(buf));
		s = buf;
		_libssh2_store_u32(&s, 1);			// Number of names being returned.
		_libssh2_store_text(&s, real_filename, strlen(real_filename));
		sftp_make_longentry(real_filename, strlen(real_filename), &sb);
		_libssh2_store_text(&s, longentry, strlen(longentry));
		sftp_stat2attr(&attrs, &sb);
		s += sftp_attr2bin(s, &attrs);
		data_len = s - buf;
		sftp->stat_state = libssh2_NB_state_created;
	}

	if (sftp->stat_state == libssh2_NB_state_created) {
		if (retcode == LIBSSH2_FX_OK) {
			rc = libssh2_sftp_server_send_message(sftp, SSH_FXP_NAME, buf,
				data_len);
			if (rc == LIBSSH2_ERROR_EAGAIN) {
				_libssh2_error(session, LIBSSH2_ERROR_EAGAIN,
					"Would block sending SSH_FXP_NAME");
				return rc;
			} else if(rc < 0) {
				_libssh2_error(session, LIBSSH2_ERROR_SOCKET_SEND,
					"Unable to send SSH_FXP_NAME");
			}
		} else {
			rc = libssh2_sftp_server_send_status(sftp, retcode);
			if (rc == LIBSSH2_ERROR_EAGAIN) {
				_libssh2_error(session, LIBSSH2_ERROR_EAGAIN,
					"Would block sending SSH_FXP_STATUS");
				return rc;
			} else if(rc < 0) {
				_libssh2_error(session, LIBSSH2_ERROR_SOCKET_SEND,
					"Unable to send SSH_FXP_STATUS");
			}
		}
		sftp->stat_state = libssh2_NB_state_idle;
	}
	return 0;
}

/* libssh2_sftp_server_realpath
 * Return real path for pathname to client.
 */
LIBSSH2_API int
libssh2_sftp_server_realpath(LIBSSH2_SFTP *sftp, const char *path,
							 unsigned int path_len)
{
    int rc;
    if(!sftp)
        return LIBSSH2_ERROR_BAD_USE;
    BLOCK_ADJUST(rc, sftp->channel->session, sftp_realpath(sftp, path,
		path_len));
    return rc;
}

/* sftp_sendpath
 * Send path name to client.
 */
static int sftp_sendpath(LIBSSH2_SFTP *sftp, const char *path,
                        unsigned int path_len, struct stat *sb)
{
	LIBSSH2_CHANNEL *channel = sftp->channel;
    LIBSSH2_SESSION *session = channel->session;
	LIBSSH2_SFTP_ATTRIBUTES attrs = {
        LIBSSH2_SFTP_ATTR_PERMISSIONS, 0, 0, 0, 0, 0, 0
    };
    size_t data_len;
    int retcode, rc, x;
    unsigned char *data, *s, *p;

	if (sftp->stat_state == libssh2_NB_state_idle) {
		retcode = LIBSSH2_FX_INVALID_FILENAME;
		if (path_len > 0) {
			retcode = LIBSSH2_FX_OK;
			memset(buf, 0, sizeof(buf));
			s = buf;
			_libssh2_store_u32(&s, 1);			// Number of names being returned.
			_libssh2_store_text(&s, path, path_len);
			sftp_make_longentry(path, path_len, sb);
			_libssh2_store_text(&s, longentry, strlen(longentry));
			sftp_stat2attr(&attrs, sb);
			s += sftp_attr2bin(s, &attrs);
			data_len = s - buf;	
		}
		sftp->stat_state = libssh2_NB_state_created;
	}

	if (sftp->stat_state == libssh2_NB_state_created) {
		if (retcode == LIBSSH2_FX_OK) {
			rc = libssh2_sftp_server_send_message(sftp, SSH_FXP_NAME, buf,
				data_len);
			if (rc == LIBSSH2_ERROR_EAGAIN) {
				_libssh2_error(session, LIBSSH2_ERROR_EAGAIN,
					"Would block sending SSH_FXP_NAME");
				return rc;
			} else if(rc < 0) {
				_libssh2_error(session, LIBSSH2_ERROR_SOCKET_SEND,
					"Unable to send SSH_FXP_NAME");
			}
		} else {
			rc = libssh2_sftp_server_send_status(sftp, 
					LIBSSH2_FX_INVALID_FILENAME);
			if (rc == LIBSSH2_ERROR_EAGAIN) {
				_libssh2_error(session, LIBSSH2_ERROR_EAGAIN,
					"Would block sending SSH_FXP_STATUS");
				return rc;
			} else if(rc < 0) {
				_libssh2_error(session, LIBSSH2_ERROR_SOCKET_SEND,
					"Unable to send SSH_FXP_STATUS");
			}
		}
		sftp->stat_state = libssh2_NB_state_idle;
	}
	return 0;
}

/* libssh2_sftp_server_sendpath
 * Send a path name to the client.
 */
LIBSSH2_API int
libssh2_sftp_server_sendpath(LIBSSH2_SFTP *sftp, const char *path,
							 unsigned int path_len, struct stat *sb)
{
    int rc;
    if(!sftp)
        return LIBSSH2_ERROR_BAD_USE;
    BLOCK_ADJUST(rc, sftp->channel->session, sftp_sendpath(sftp, path,
		path_len, sb));
    return rc;
}

/* libssh2_sftp_get_ccsid
 * Returns the ccsid stored in the SFTP_HANDLE
 */
LIBSSH2_API int
libssh2_sftp_get_ccsid(LIBSSH2_SFTP_HANDLE *handle)
{
    if (!handle) return -1;

    return handle->ccsid;
}

/* libssh2_sftp_set_recsep
 * Set the record seperator flag. If on, canonicalize or decanonicalise
 * record seperators.
 */
LIBSSH2_API int
libssh2_sftp_set_recsep(LIBSSH2_SFTP_HANDLE *handle, int recsep)
{
    if (!handle) return -1;

    handle->recsep = recsep;
	return 0;
}

/* libssh2_sftp_remove_blanks
 * Set the remove trailing blanks flag. If on, remove padded
 * blanks from lines.
 */
LIBSSH2_API int
libssh2_sftp_remove_blanks(LIBSSH2_SFTP_HANDLE *handle, int remove)
{
    if (!handle) return -1;

    handle->remove_blanks = remove;
	return 0;
}

/* libssh2_sftp_set_CRLF
 * Set the line-end chars for text records.
 */
LIBSSH2_API int
libssh2_sftp_set_CRLF(LIBSSH2_SFTP_HANDLE *handle, const char* line_end)
{
    if (!handle) return -1;

	if (strlen(line_end) > 2) return -1;

	strcpy(handle->CRLF, line_end);

	return 0;
}

/* libssh2_sftp_set_format
 * Set the flag to do record formatting.
 */
LIBSSH2_API int
libssh2_sftp_set_format(LIBSSH2_SFTP_HANDLE *handle, int format)
{
    if (!handle) return -1;

	handle->format_records = format;

	return 0;
}

/* libssh2_sftp_set_delimiter
 * Set the delimiter used for record formatting.
 */
LIBSSH2_API int
libssh2_sftp_set_delimiter(LIBSSH2_SFTP_HANDLE *handle, char *delimiter)
{
    if (!handle) return -1;

	memcpy(&handle->format_delimiter, delimiter, 8);

	return 0;
}

/* libssh2_sftp_get_filename
 * Return pointer to filename in handle.
 */
LIBSSH2_API char*
libssh2_sftp_get_filename(LIBSSH2_SFTP_HANDLE *handle)
{
    if (!handle) return NULL;

	return handle->filename;
}

/* libssh2_sftp_set_open_options
 * Set the options used for the next file open.
 */
LIBSSH2_API int
libssh2_sftp_set_open_options( int fmtstream, int recsep, int trimb, int truncate,
							  int format, char *line_end, char *delimiter)
{
	fmtStream = fmtstream;
	recordSep = recsep;
	trimBlanks = trimb;
	truncateRecords = truncate;
	formatRecords = format;
	strcpy(lineEnd, default_CRLF);
	memset(formatDelim, 0, sizeof(formatDelim));

	if (line_end) strcpy(lineEnd, line_end);

	if (delimiter) memcpy(formatDelim, delimiter, 8);

	return 0;
}

/* libssh2_sftp_set_appflag
 * Set the applications flags in the SFTP Handle.
 */
LIBSSH2_API int
libssh2_sftp_set_appflag( LIBSSH2_SFTP_HANDLE *handle, int flagNum, int value)
{

	if (!handle) return -1;

	switch(flagNum) {
		case 1:
			handle->app_flag1 = value;
			break;
		case 2:
			handle->app_flag2 = value;
			break;
		case 3:
			handle->app_flag3 = value;
			break;
		case 4:
			handle->app_flag4 = value;
			break;
		case 5:
			handle->app_flag5 = value;
			break;
		default:
			return -1;
	}

	return 0;

}

/* libssh2_sftp_get_appflag
 * Get an application flag from the SFTP Handle.
 */
LIBSSH2_API int
libssh2_sftp_get_appflag( LIBSSH2_SFTP_HANDLE *handle, int flagNum)
{

	if (!handle) return -1;

	switch(flagNum) {
		case 1:
			return handle->app_flag1;
		case 2:
			return handle->app_flag2;
		case 3:
			return handle->app_flag3;
		case 4:
			return handle->app_flag4;
		case 5:
			return handle->app_flag5;
		default:
			return -1;
	}
}

/* libssh2_sftp_set_appptr
 * Set the applications pointers in the SFTP Handle.
 */
LIBSSH2_API int
libssh2_sftp_set_appptr( LIBSSH2_SFTP_HANDLE *handle, int ptrNum, void* ptr)
{

	if (!handle) return -1;

	switch(ptrNum) {
		case 1:
			handle->app_ptr1 = ptr;
			break;
		case 2:
			handle->app_ptr2 = ptr;
			break;
		case 3:
			handle->app_ptr3 = ptr;
			break;
		case 4:
			handle->app_ptr4 = ptr;
			break;
		case 5:
			handle->app_ptr5 = ptr;
			break;
		default:
			return -1;
	}

	return 0;

}

/* libssh2_sftp_get_appptr
 * Get an applications pointer from the SFTP Handle.
 */
LIBSSH2_API void*
libssh2_sftp_get_appptr( LIBSSH2_SFTP_HANDLE *handle, int ptrNum)
{

	if (!handle) return NULL;

	switch(ptrNum) {
		case 1:
			return handle->app_ptr1;
		case 2:
			return handle->app_ptr2;
		case 3:
			return handle->app_ptr3;
		case 4:
			return handle->app_ptr4;
		case 5:
			return handle->app_ptr5;
		default:
			return NULL;
	}
}

/* libssh2_sftp_get_bytes_in_file
 * Get counter of the file bytes.
 */
LIBSSH2_API int
libssh2_sftp_get_bytes_in_file( LIBSSH2_SFTP_HANDLE *handle)
{
	if (!handle) return -1;

	return handle->bytes_in_file;
}

/* libssh2_sftp_get_last_errno
 * Get last errno for sftp session.
 */
LIBSSH2_API int
libssh2_sftp_get_last_errno( LIBSSH2_SFTP *sftp)
{
	if (!sftp) return -1;

	if (sftp->last_errno == EAGAIN) return 0;

	return sftp->last_errno;
}

/* libssh2_sftp_get_handle_type
 * Get handle type from handle.
 * Returns 0 if FILE, 1 if DIR.
 */
LIBSSH2_API int
libssh2_sftp_get_handle_type( LIBSSH2_SFTP_HANDLE *handle)
{
	if (!handle) return -1;

	if (handle->handle_type == LIBSSH2_SFTP_HANDLE_FILE)
		return 0;

	return 1;
}

/* libssh2_sftp_is_write
 * Test: Is this handle in write_mode
 * Returns 0 if READ, 1 if WRITE.
 */
LIBSSH2_API int
libssh2_sftp_is_write( LIBSSH2_SFTP_HANDLE *handle)
{
	if (!handle) return -1;

	return handle->write_mode;
}


/////////////////////////////////////////////////////////////////////////////////
#if 0

/* *******************************
 * SFTP File and Directory Ops *
 ******************************* */



/* sftp_symlink
 * Read or set a symlink
 */
static int sftp_symlink(LIBSSH2_SFTP *sftp, const char *path,
                        unsigned int path_len, char *target,
                        unsigned int target_len, int link_type)
{
    LIBSSH2_CHANNEL *channel = sftp->channel;
    LIBSSH2_SESSION *session = channel->session;
    size_t data_len, link_len;
    /* 13 = packet_len(4) + packet_type(1) + request_id(4) + path_len(4) */
    ssize_t packet_len =
        path_len + 13 +
        ((link_type == LIBSSH2_SFTP_SYMLINK) ? (4 + target_len) : 0);
    unsigned char *s, *data;
    static const unsigned char link_responses[2] =
        { SSH_FXP_NAME, SSH_FXP_STATUS };
    int rc;

    if ((sftp->version < 3) && (link_type != LIBSSH2_SFTP_REALPATH)) {
        return _libssh2_error(session, LIBSSH2_ERROR_SFTP_PROTOCOL,
                              "Server does not support SYMLINK or READLINK");
    }

    if (sftp->symlink_state == libssh2_NB_state_idle) {
        s = sftp->symlink_packet = LIBSSH2_ALLOC(session, packet_len);
        if (!sftp->symlink_packet) {
            return _libssh2_error(session, LIBSSH2_ERROR_ALLOC,
                                  "Unable to allocate memory for "
                                  "SYMLINK/READLINK/REALPATH packet");
        }

        _libssh2_debug(session, LIBSSH2_TRACE_SFTP, "%s %s on %s",
                       (link_type ==
                        LIBSSH2_SFTP_SYMLINK) ? "Creating" : "Reading",
                       (link_type ==
                        LIBSSH2_SFTP_REALPATH) ? "realpath" : "symlink", path);

        _libssh2_store_u32(&s, packet_len - 4);

        switch (link_type) {
        case LIBSSH2_SFTP_REALPATH:
            *(s++) = SSH_FXP_REALPATH;
            break;

        case LIBSSH2_SFTP_SYMLINK:
            *(s++) = SSH_FXP_SYMLINK;
            break;

        case LIBSSH2_SFTP_READLINK:
        default:
            *(s++) = SSH_FXP_READLINK;
        }
        sftp->symlink_request_id = sftp->request_id++;
        _libssh2_store_u32(&s, sftp->symlink_request_id);
        _libssh2_store_text(&s, path, path_len);

        if (link_type == LIBSSH2_SFTP_SYMLINK)
            _libssh2_store_text(&s, target, target_len);

        sftp->symlink_state = libssh2_NB_state_created;
    }

    if (sftp->symlink_state == libssh2_NB_state_created) {
        rc = _libssh2_channel_write(channel, 0, (char *) sftp->symlink_packet,
                                    packet_len);
        if (rc == LIBSSH2_ERROR_EAGAIN) {
            return rc;
        } else if (packet_len != rc) {
            LIBSSH2_FREE(session, sftp->symlink_packet);
            sftp->symlink_packet = NULL;
            sftp->symlink_state = libssh2_NB_state_idle;
            return _libssh2_error(session, LIBSSH2_ERROR_SOCKET_SEND,
                                  "Unable to send SYMLINK/READLINK command");
        }
        LIBSSH2_FREE(session, sftp->symlink_packet);
        sftp->symlink_packet = NULL;

        sftp->symlink_state = libssh2_NB_state_sent;
    }

    rc = sftp_packet_requirev(sftp, 2, link_responses,
                              sftp->symlink_request_id, &data,
                              &data_len);
    if (rc == LIBSSH2_ERROR_EAGAIN) {
        return rc;
    }
    else if (rc) {
        sftp->symlink_state = libssh2_NB_state_idle;
        return _libssh2_error(session, LIBSSH2_ERROR_SOCKET_TIMEOUT,
                              "Timeout waiting for status message");
    }

    sftp->symlink_state = libssh2_NB_state_idle;

    if (data[0] == SSH_FXP_STATUS) {
        int retcode;

        retcode = _libssh2_ntohu32(data + 5);
        LIBSSH2_FREE(session, data);
        if (retcode == LIBSSH2_FX_OK) {
            return 0;
        } else {
            sftp->last_errno = retcode;
            return _libssh2_error(session, LIBSSH2_ERROR_SFTP_PROTOCOL,
                                  "SFTP Protocol Error");
        }
    }

    if (_libssh2_ntohu32(data + 5) < 1) {
        LIBSSH2_FREE(session, data);
        return _libssh2_error(session, LIBSSH2_ERROR_SFTP_PROTOCOL,
                              "Invalid READLINK/REALPATH response, "
                              "no name entries");
    }

    link_len = _libssh2_ntohu32(data + 9);
    if (link_len >= target_len) {
        link_len = target_len - 1;
    }
    memcpy(target, data + 13, link_len);
#ifdef EBCDIC
	libssh2_make_ebcdic(target, link_len);
#endif
    target[link_len] = 0;
    LIBSSH2_FREE(session, data);

    return link_len;
}

/* libssh2_sftp_symlink_ex
 * Read or set a symlink
 */
LIBSSH2_API int
libssh2_sftp_symlink_ex(LIBSSH2_SFTP *sftp, const char *path,
                        unsigned int path_len, char *target,
                        unsigned int target_len, int link_type)
{
    int rc;
    if(!sftp)
        return LIBSSH2_ERROR_BAD_USE;
    BLOCK_ADJUST(rc, sftp->channel->session,
                 sftp_symlink(sftp, path, path_len, target, target_len,
                              link_type));
    return rc;
}

/* libssh2_sftp_last_error
 * Returns the last error code reported by SFTP
 */
LIBSSH2_API unsigned long
libssh2_sftp_last_error(LIBSSH2_SFTP *sftp)
{
    if(!sftp)
       return 0;

    return sftp->last_errno;
}

#endif