#ifndef __LIBSSH2_MESSAGES_H
#define __LIBSSH2_MESSAGES_H

/* Copyright (c) 2010-2015, Liaison Technologies, Inc. (formerly nuBridges, Inc.)
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
 *
 * This file handles message packets for libssh2 server-side 
 * support.
 */

struct _LIBSSH2_MESSAGE {
    LIBSSH2_SERVER_SESSION*	server;
	LIBSSH2_SESSION*		session;
	LIBSSH2_SFTP*			sftp;
    int				type;			// message type
	int				subtype;		// message sub-type
	int             request_id;		// request id from message.
	unsigned char*	msg_ptr;		// pointer to message packet.
	unsigned int	msg_len;		// length of message packet.
	unsigned int	offset;			// current offset into packet.
	unsigned char*	msg_resp;		// Data for message response.
	unsigned int	msg_resp_len;	// Len(data in msg_resp).
	void*			data_area;		// Data area to be returned.
	unsigned char*	channel_buf;	// Buffer for channel data.
	size_t			channel_buf_len; // Length of channel data.
};

typedef struct _LIBSSH2_MESSAGE  LIBSSH2_MESSAGE;

/*
 * _libssh2_message_get
 *
 * Get a message packet from the brigade, format it into a 
 * LIBSSH2_MESSAGE structure and return it to the caller.
 * Returns LIBSSH2_MESSAGE on success, NULL on failure.
 *
 */
LIBSSH2_MESSAGE* _libssh2_message_get(LIBSSH2_SERVER_SESSION* server);

/*
 * _libssh2_message_reply_userauth
 *
 * Get a service request packet from the brigade, format it into a 
 * LIBSSH2_MESSAGE structure and return it to the caller.
 * Returns LIBSSH2_MESSAGE on success, NULL on failure.
 *
 */
int _libssh2_message_default_reply(LIBSSH2_MESSAGE* message, 
								   int success, char* resp_data);

#endif /* __LIBSSH2_MESSAGES_H */