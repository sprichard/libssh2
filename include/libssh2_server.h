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

#ifndef LIBSSH2_SERVER_H
#define LIBSSH2_SERVER_H 1

#include "libssh2.h"

#ifndef WIN32
#include <unistd.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _LIBSSH2_SERVER			LIBSSH2_SERVER;
typedef struct _LIBSSH2_SERVER_SESSION	LIBSSH2_SERVER_SESSION;
typedef struct _LIBSSH2_MESSAGE			LIBSSH2_MESSAGE;

/* Let's start with Version 3 (The version found in OpenSSH) and go from there
 */
#define LIBSSH2_SERVER_VERSION      3

/* Server API */
LIBSSH2_API LIBSSH2_SERVER* libssh2_server_init(unsigned long ipAddr, int portNum,
					char* pubkeyfile, char* privkeyfile);
LIBSSH2_API int libssh2_server_shutdown(LIBSSH2_SERVER* server);
LIBSSH2_API int libssh2_server_listen(LIBSSH2_SERVER *server);
LIBSSH2_API LIBSSH2_SERVER_SESSION* libssh2_server_accept(LIBSSH2_SERVER* server);
LIBSSH2_API LIBSSH2_SERVER_SESSION* libssh2_server_accept_socket(LIBSSH2_SERVER* server,
																int sock);
LIBSSH2_API int libssh2_server_startup(LIBSSH2_SERVER_SESSION* server);
LIBSSH2_API int libssh2_server_disconnect(LIBSSH2_SERVER_SESSION* server);

/* SFTP Server API */

LIBSSH2_API LIBSSH2_SFTP *libssh2_sftp_server_init(LIBSSH2_CHANNEL* sftp_channel);
LIBSSH2_API LIBSSH2_MESSAGE *libssh2_sftp_server_request(LIBSSH2_SFTP *sftp);
LIBSSH2_API int libssh2_sftp_server_send_status(LIBSSH2_SFTP *sftp, int error_code);
LIBSSH2_API int libssh2_sftp_server_send_errno(LIBSSH2_SFTP *sftp, int error_code);
LIBSSH2_API int libssh2_sftp_server_send_message(LIBSSH2_SFTP *sftp, int msg_type,
						char* data, int data_len);
LIBSSH2_API LIBSSH2_SFTP_HANDLE *libssh2_sftp_server_opendir(LIBSSH2_SFTP *sftp,
						const char *dirname, unsigned int dirname_len);
LIBSSH2_API LIBSSH2_SFTP_HANDLE *libssh2_sftp_server_open(LIBSSH2_SFTP *sftp,
						const char *filename, unsigned int filename_len, size_t flags,
						const char *attrs, int ccsid);
LIBSSH2_API int libssh2_sftp_server_close_handle(LIBSSH2_SFTP_HANDLE *hnd);
LIBSSH2_API LIBSSH2_SFTP_HANDLE* libssh2_sftp_handle_locate(LIBSSH2_SFTP* sftp,
						char* handle, int handle_len);
LIBSSH2_API int libssh2_sftp_server_stat(LIBSSH2_SFTP *sftp, const char *path,
						unsigned int path_len, int stat_type,
						unsigned char* bin_attrs);
LIBSSH2_API int libssh2_sftp_server_fstat(LIBSSH2_SFTP_HANDLE *hnd, int stat_type,
						unsigned char* bin_attrs);
LIBSSH2_API int libssh2_sftp_server_unlink(LIBSSH2_SFTP *sftp, const char *filename,
						unsigned int filename_len);
LIBSSH2_API int libssh2_sftp_server_mkdir(LIBSSH2_SFTP *sftp, const char *path,
						unsigned int path_len, unsigned char* attrs);
LIBSSH2_API int libssh2_sftp_server_rmdir(LIBSSH2_SFTP *sftp, const char *path,
						unsigned int path_len);
LIBSSH2_API int libssh2_sftp_server_rename(LIBSSH2_SFTP *sftp, 
						const char *source_filename, unsigned int source_filename_len,
						const char *dest_filename, unsigned int dest_filename_len,
						long flags);
LIBSSH2_API int libssh2_sftp_server_realpath(LIBSSH2_SFTP *sftp, const char *path,
						unsigned int path_len);
LIBSSH2_API int libssh2_sftp_server_readdir(LIBSSH2_SFTP_HANDLE *hnd);
LIBSSH2_API int libssh2_sftp_server_read(LIBSSH2_SFTP_HANDLE *hnd,
						libssh2_uint64_t offset, size_t bytes_requested);
LIBSSH2_API int libssh2_sftp_server_write(LIBSSH2_SFTP_HANDLE *hnd, libssh2_uint64_t offset,
						const char *buffer, size_t count);
LIBSSH2_API int libssh2_sftp_server_fstatvfs(LIBSSH2_SFTP_HANDLE *hnd);
LIBSSH2_API int libssh2_sftp_server_statvfs(LIBSSH2_SFTP *sftp, unsigned char* path,
						int path_len);
LIBSSH2_API int libssh2_sftp_server_sendpath(LIBSSH2_SFTP *sftp, const char *path,
						unsigned int path_len, struct stat *sb);
LIBSSH2_API int libssh2_sftp_get_ccsid(LIBSSH2_SFTP_HANDLE *sftp);
LIBSSH2_API int libssh2_sftp_set_recsep(LIBSSH2_SFTP_HANDLE *handle, int recsep);
LIBSSH2_API int libssh2_sftp_remove_blanks(LIBSSH2_SFTP_HANDLE *handle, int remove);
LIBSSH2_API int libssh2_sftp_set_CRLF(LIBSSH2_SFTP_HANDLE *handle, const char* line_end);
LIBSSH2_API int libssh2_sftp_set_format(LIBSSH2_SFTP_HANDLE *handle, int format);
LIBSSH2_API int libssh2_sftp_set_delimiter(LIBSSH2_SFTP_HANDLE *handle, char *delimiter);
LIBSSH2_API int libssh2_sftp_set_open_options( int fmtstream, int recsep, int trimb,
							int truncate, int format, char *line_end, char *delimiter);
LIBSSH2_API char* libssh2_sftp_get_filename(LIBSSH2_SFTP_HANDLE *handle);
LIBSSH2_API void libssh2_set_translate_tables(char *a2e, char *e2a);
LIBSSH2_API int libssh2_sftp_set_appflag( LIBSSH2_SFTP_HANDLE *handle, int flagNum,
							int value);
LIBSSH2_API int libssh2_sftp_get_appflag( LIBSSH2_SFTP_HANDLE *handle, int flagNum);
LIBSSH2_API int libssh2_sftp_set_appptr( LIBSSH2_SFTP_HANDLE *handle, int ptrNum,
							void* ptr);
LIBSSH2_API void* libssh2_sftp_get_appptr( LIBSSH2_SFTP_HANDLE *handle, int ptrNum);
LIBSSH2_API char* libssh2_server_get_remote_banner(LIBSSH2_SERVER_SESSION* server);
LIBSSH2_API int libssh2_sftp_get_bytes_in_file( LIBSSH2_SFTP_HANDLE *handle);
LIBSSH2_API int libssh2_sftp_get_last_errno( LIBSSH2_SFTP *sftp);
LIBSSH2_API int libssh2_sftp_get_handle_type( LIBSSH2_SFTP_HANDLE *handle);
LIBSSH2_API int libssh2_sftp_is_write( LIBSSH2_SFTP_HANDLE *handle);
LIBSSH2_API void libssh2_server_keepalive_config (LIBSSH2_SERVER_SESSION *server,
                          int want_reply, unsigned interval);
LIBSSH2_API int libssh2_server_last_error(LIBSSH2_SERVER_SESSION *server,
						char **errmsg, int *errmsg_len, int want_buf);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* LIBSSH2_SERVER_H */
