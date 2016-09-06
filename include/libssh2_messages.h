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

#ifndef LIBSSH2_MESSAGES_H
#define LIBSSH2_MESSAGES_H 1

#include "libssh2.h"

#ifndef WIN32
#include <unistd.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _LIBSSH2_MESSAGE  LIBSSH2_MESSAGE;

/* SSH Packet Types -- Defined by internet draft */
/* Transport Layer */
#define SSH_MSG_DISCONNECT                          1
#define SSH_MSG_IGNORE                              2
#define SSH_MSG_UNIMPLEMENTED                       3
#define SSH_MSG_DEBUG                               4
#define SSH_MSG_SERVICE_REQUEST                     5
#define SSH_MSG_SERVICE_ACCEPT                      6

#define SSH_MSG_KEXINIT                             20
#define SSH_MSG_NEWKEYS                             21

/* diffie-hellman-group1-sha1 */
#define SSH_MSG_KEXDH_INIT                          30
#define SSH_MSG_KEXDH_REPLY                         31

/* diffie-hellman-group-exchange-sha1 */
#define SSH_MSG_KEX_DH_GEX_REQUEST_OLD              30
#define SSH_MSG_KEX_DH_GEX_REQUEST                  34
#define SSH_MSG_KEX_DH_GEX_GROUP                    31
#define SSH_MSG_KEX_DH_GEX_INIT                     32
#define SSH_MSG_KEX_DH_GEX_REPLY                    33

/* User Authentication */
#define SSH_MSG_USERAUTH_REQUEST                    50
#define SSH_MSG_USERAUTH_FAILURE                    51
#define SSH_MSG_USERAUTH_SUCCESS                    52
#define SSH_MSG_USERAUTH_BANNER                     53

/* "public key" method */
#define SSH_MSG_USERAUTH_PK_OK                      60
/* "password" method */
#define SSH_MSG_USERAUTH_PASSWD_CHANGEREQ           60
/* "keyboard-interactive" method */
#define SSH_MSG_USERAUTH_INFO_REQUEST               60
#define SSH_MSG_USERAUTH_INFO_RESPONSE              61

/* Channels */
#define SSH_MSG_GLOBAL_REQUEST                      80
#define SSH_MSG_REQUEST_SUCCESS                     81
#define SSH_MSG_REQUEST_FAILURE                     82

#define SSH_MSG_CHANNEL_OPEN                        90
#define SSH_MSG_CHANNEL_OPEN_CONFIRMATION           91
#define SSH_MSG_CHANNEL_OPEN_FAILURE                92
#define SSH_MSG_CHANNEL_WINDOW_ADJUST               93
#define SSH_MSG_CHANNEL_DATA                        94
#define SSH_MSG_CHANNEL_EXTENDED_DATA               95
#define SSH_MSG_CHANNEL_EOF                         96
#define SSH_MSG_CHANNEL_CLOSE                       97
#define SSH_MSG_CHANNEL_REQUEST                     98
#define SSH_MSG_CHANNEL_SUCCESS                     99
#define SSH_MSG_CHANNEL_FAILURE                     100

typedef struct _LIBSSH2_MESSAGE			LIBSSH2_MESSAGE;

/* Message Handling API */

/*
 * proto libssh2_message_get
 *
 * Returns: Pointer to LIBSSH2_MESSAGE on success, or NULL on failure
 * Any memory allocated by libssh2 will use alloc/realloc/free
 * callbacks in session.
 */
LIBSSH2_API LIBSSH2_MESSAGE*
libssh2_message_get(LIBSSH2_SERVER_SESSION* server);

/*
 * _libssh2_message_get_channel
 *
 * Get a channel message packet from the brigade, format it into a 
 * LIBSSH2_MESSAGE structure and return it to the caller.
 * Returns LIBSSH2_MESSAGE on success, NULL on failure.
 *
 */
LIBSSH2_MESSAGE* _libssh2_message_get_channel(LIBSSH2_SERVER_SESSION* server,
											  LIBSSH2_CHANNEL* channel);

/*
 * proto libssh2_message_default_reply
 *
 * Reply to a message.
 *
 * server: LIBSSH2_SESSION struct allocated and owned by the calling program
 * Returns: Pointer to LIBSSH2_MESSAGE on success, or NULL on failure
 * Any memory allocated by libssh2 will use alloc/realloc/free
 * callbacks in session.
 */
LIBSSH2_API int
libssh2_message_default_reply(LIBSSH2_MESSAGE* message, 
							  int success, char* resp_data);

/*
 * libssh2_message_free
 *
 * Free storage for a LIBSSH2_MESSAGE.
 * Returns 0 on success, -1 on failure.
 *
 */
LIBSSH2_API int libssh2_message_free(LIBSSH2_MESSAGE* message);

/*
 * libssh2_message_type
 *
 * Return the message type for the specified message.
 * Returns 0 on success, -1 on failure.
 *
 */
LIBSSH2_API int libssh2_message_type(LIBSSH2_MESSAGE* message);

/*
 * libssh2_message_parm
 *
 * Return the next parameter from the message.
 * Returns 0 on success, 1 on EOM, -1 on failure.
 *
 */
LIBSSH2_API int libssh2_message_parm(LIBSSH2_MESSAGE* message, char** parm, 
									 size_t* parmlen, int translate);

/*
 * libssh2_message_parm_text
 *
 * Return the next parameter from the message. The parameter is text and
 * will be translated as necessary.
 * Returns 0 on success, 1 on EOM, -1 on failure.
 *
 */
LIBSSH2_API int libssh2_message_parm_text(LIBSSH2_MESSAGE* message, char** parm, size_t* parmlen);

/*
 * libssh2_message_parm_str
 *
 * Return the next parameter from the message. The parameter is a string and
 * will not be translated.
 * Returns 0 on success, 1 on EOM, -1 on failure.
 *
 */
LIBSSH2_API int libssh2_message_parm_str(LIBSSH2_MESSAGE* message, char** parm, size_t* parmlen);

/*
 * libssh2_message_parm_u32
 *
 * Return the next parameter from the message. The parameter is a 32-bit numeric.
 * Returns 0 on success, 1 on EOM, -1 on failure.
 *
 */
LIBSSH2_API int libssh2_message_parm_u32(LIBSSH2_MESSAGE* message, size_t* parm);

/*
 * libssh2_message_parm_u64
 *
 * Return the next parameter from the message. The parameter is a 64-bit numeric.
 * Returns 0 on success, 1 on EOM, -1 on failure.
 *
 */
LIBSSH2_API int libssh2_message_parm_u64(LIBSSH2_MESSAGE* message, libssh2_uint64_t* parm);

/*
 * libssh2_message_parm_bytes
 *
 * Return the next parameter from the message. The parameter is a series of bytes,
 * the length of which is specified in the parmlen parameter.
 * Returns 0 on success, 1 on EOM, -1 on failure.
 *
 */
LIBSSH2_API int libssh2_message_parm_bytes(LIBSSH2_MESSAGE* message, char** parm, size_t parmlen);

/*
 * libssh2_message_data_area
 *
 * Return the data area address created by the message processing routine.
 * Returns pointer on success, NULL on failure.
 *
 */
LIBSSH2_API void* libssh2_message_data_area(LIBSSH2_MESSAGE* message);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* LIBSSH2_MESSAGES_H */
