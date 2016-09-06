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

#include "libssh2_priv.h"
#include <errno.h>
#include <fcntl.h>
#include <assert.h>
#include "transport.h"
#include "session.h"
#include "misc.h"
#include "server.h"
#include "packet.h"
#include "channel.h"
#include "libssh2_messages.h"
#include "messages.h"

#define SUCCESS 1
#define FAIL 0

/*
 * proto libssh2_message_get
 *
 * server: LIBSSH2_SESSION struct allocated and owned by the calling program
 * Returns: Pointer to LIBSSH2_MESSAGE on success, or NULL on failure
 * Any memory allocated by libssh2 will use alloc/realloc/free
 * callbacks in session.
 */
LIBSSH2_API LIBSSH2_MESSAGE*
libssh2_message_get(LIBSSH2_SERVER_SESSION* server)
{
    LIBSSH2_MESSAGE* msg;

    BLOCK_ADJUST_ERRNO(msg, server->session, _libssh2_message_get(server) );

    return msg;
}

/*
 * _libssh2_message_get
 *
 * Get a message packet from the brigade, format it into a 
 * LIBSSH2_MESSAGE structure and return it to the caller.
 * Returns LIBSSH2_MESSAGE on success, NULL on failure.
 *
 */
LIBSSH2_MESSAGE* _libssh2_message_get(LIBSSH2_SERVER_SESSION* server)
{
	message_processor_state_t*	msg_state;
	int					rc = 0, ret = 0;
	int					length;
	unsigned char*		channel_type;
	size_t				channel_type_len;
	unsigned char*		want_reply;
	unsigned char*		request_type;
	size_t				request_type_len;
	unsigned char*		subsys_type;
	size_t				subsys_type_len;
	unsigned int		channel_id;
	unsigned int		window_size;
	unsigned int		packet_size;
	unsigned char*		pkt_data;
	size_t				pkt_data_len;
	LIBSSH2_SESSION*	session;
	LIBSSH2_MESSAGE*	message;
	LIBSSH2_PACKET*		packet = NULL;
	LIBSSH2_CHANNEL*	channel = NULL;

	if (!server)
		return NULL;

	session = server->session;
	msg_state = &server->msg_state;

	message = LIBSSH2_ALLOC(session, sizeof(LIBSSH2_MESSAGE));
next_message:
	memset(message, 0, sizeof(LIBSSH2_MESSAGE));
	message->server = server;
	message->session = session;

	// If we have an old message packet laying around...
	if (msg_state->m_packet) {
		LIBSSH2_FREE(session, msg_state->m_packet);
		msg_state->m_packet = NULL;
	}

	if (msg_state->state == libssh2_NB_state_idle) {

		while(!msg_state->m_packet) {
			packet = _libssh2_list_first(&session->packets);
			while(packet) {
				if ((packet->data[0] > 29) && (packet->data[0] < 40)) {
					// Skip Key Exchange packets, we do not handle those.
					packet = _libssh2_list_next(&packet->node);
					continue;
				}
				msg_state->m_packet = LIBSSH2_ALLOC(session, packet->data_len);
				memcpy(msg_state->m_packet, packet->data, packet->data_len);
				msg_state->m_packet_len = packet->data_len;
				_libssh2_list_remove(&packet->node);
				LIBSSH2_FREE(session, packet);
				packet = NULL;
				break;
			}
			if (msg_state->m_packet) break;
			ret = _libssh2_transport_read(session);
			if (session->socket_state == LIBSSH2_SOCKET_DISCONNECTED) break;
			if (ret == LIBSSH2_ERROR_EAGAIN){
				_libssh2_error(session, LIBSSH2_ERROR_EAGAIN,
					"Would block waiting for SFTP request");
	            return NULL;
			}
			else if (ret < 0) {
				/* an error which is not just because of blocking */
				ret = _libssh2_error(session, LIBSSH2_ERROR_TIMEOUT,
							"Error reading for packet");
				libssh2_message_free(message);
				message = NULL;
				goto clean_exit;
			}
			// Do timeout?
		}

		msg_state->state = libssh2_NB_state_created;
	}

	if (msg_state->state == libssh2_NB_state_created) {
		if( session->socket_state == LIBSSH2_SOCKET_DISCONNECTED) {
			message->msg_ptr = NULL;
			message->msg_len = 0;
			message->offset = 0;
			message->type = SSH_MSG_DISCONNECT;
		} else {
			// process packet
			message->msg_ptr = msg_state->m_packet;
			message->msg_len = msg_state->m_packet_len;
			message->offset = 1;
			message->type = msg_state->m_packet[0];
		}
		switch(message->type) {
			case SSH_MSG_CHANNEL_OPEN:
				libssh2_message_parm_text(message, &channel_type, &channel_type_len);
				libssh2_message_parm_u32(message, &channel_id);
				libssh2_message_parm_u32(message, &window_size);
				libssh2_message_parm_u32(message, &packet_size);
				libssh2_message_parm_text(message, &pkt_data, &pkt_data_len);
				message->offset = 1;
				session->open_channel = LIBSSH2_ALLOC(session, sizeof(LIBSSH2_CHANNEL));
				if (!session->open_channel) {
					_libssh2_error(session, LIBSSH2_ERROR_ALLOC,
						"Unable to allocate space for channel data");
					libssh2_message_default_reply(message, FAIL, NULL);
					// Get another message.
					goto new_message;
				}
				memset(session->open_channel, 0, sizeof(LIBSSH2_CHANNEL));
				session->open_channel->channel_type_len = channel_type_len;
				session->open_channel->channel_type =
					LIBSSH2_ALLOC(session, channel_type_len);
				if (!session->open_channel->channel_type) {
					_libssh2_error(session, LIBSSH2_ERROR_ALLOC,
						"Failed allocating memory for channel type name");
					LIBSSH2_FREE(session, session->open_channel);
					session->open_channel = NULL;
					libssh2_message_default_reply(message, FAIL, NULL);
					// Get another message.
					goto new_message;
				}
				message->data_area = (void*)session->open_channel;
				session->open_channel->session = session;
				session->open_local_channel = _libssh2_channel_nextid(session);
				memcpy(session->open_channel->channel_type, channel_type,
					channel_type_len);
#ifdef EBCDIC
				// Convert channel_type back to ascii for future use.
				libssh2_make_ascii(channel_type, channel_type_len);
#endif
				session->open_channel->local.id = session->open_local_channel;
				session->open_channel->remote.id = channel_id;
				session->open_channel->remote.window_size = window_size;
				session->open_channel->remote.window_size_initial = window_size;
				session->open_channel->remote.packet_size = packet_size;
				session->open_channel->local.window_size = window_size;
				session->open_channel->local.window_size_initial = window_size;
				session->open_channel->local.packet_size = packet_size;
				_libssh2_list_add(&session->channels,
                          &session->open_channel->node);
				message->msg_resp_len = 16;
				message->msg_resp = LIBSSH2_ALLOC(session, message->msg_resp_len);
				if (!message->msg_resp) {
					_libssh2_error(session, LIBSSH2_ERROR_ALLOC,
						"Failed allocating memory for message response data");
					libssh2_message_default_reply(message, FAIL, NULL);
					// Get another message.
					goto new_message;
				}
				msg_state->s = message->msg_resp;
				_libssh2_store_u32(&msg_state->s, channel_id);
				_libssh2_store_u32(&msg_state->s, session->open_channel->local.id);
				_libssh2_store_u32(&msg_state->s, window_size);
				_libssh2_store_u32(&msg_state->s, packet_size);
				break;
			case SSH_MSG_CHANNEL_REQUEST:
				libssh2_message_parm_u32(message, &channel_id);
				libssh2_message_parm_text(message, &request_type, &request_type_len);
				libssh2_message_parm_bytes(message, &want_reply, 1);
				libssh2_message_parm_text(message, &subsys_type, &subsys_type_len);
				message->offset = 1;
				channel = _libssh2_channel_locate(session, channel_id);
				if (!channel) {
					channel_id = -1;
				}
				if ( channel && 
					(!memcmp(request_type, "subsystem", 9)) && 
					(!memcmp(subsys_type, "sftp", 4))) {
					// Make this channel an sftp channel
					channel_id = channel->remote.id;
					message->data_area = (void*)channel;
				}
#ifdef EBCDIC
				// Convert fields back to ascii for future use.
				libssh2_make_ascii(request_type, request_type_len);
				libssh2_make_ascii(subsys_type, subsys_type_len);
#endif
				message->msg_resp_len = 4;
				message->msg_resp = LIBSSH2_ALLOC(session, message->msg_resp_len);
				if (!message->msg_resp) {
					_libssh2_error(session, LIBSSH2_ERROR_ALLOC,
						"Failed allocating memory for message response data");
					libssh2_message_default_reply(message, FAIL, NULL);
					// Get another message.
					goto new_message;
				}
				msg_state->s = message->msg_resp;
				_libssh2_store_u32(&msg_state->s, channel_id);
				break;
// The following message types are implemented, but require no processing here.
			case SSH_MSG_CHANNEL_DATA:
				break;
			case SSH_MSG_CHANNEL_CLOSE:
				break;
			case SSH_MSG_CHANNEL_EOF:
				break;
			case SSH_MSG_SERVICE_REQUEST:
				break;
// The following message types are not yet implemented
			case SSH_MSG_DISCONNECT:
			case SSH_MSG_IGNORE:
			case SSH_MSG_UNIMPLEMENTED:
			case SSH_MSG_DEBUG:
			case SSH_MSG_SERVICE_ACCEPT:
			case SSH_MSG_KEXINIT:
			case SSH_MSG_NEWKEYS:
			case SSH_MSG_USERAUTH_REQUEST:
			case SSH_MSG_USERAUTH_FAILURE:
			case SSH_MSG_USERAUTH_SUCCESS:
			case SSH_MSG_USERAUTH_BANNER:
			case SSH_MSG_USERAUTH_INFO_REQUEST:
			case SSH_MSG_USERAUTH_INFO_RESPONSE:
			case SSH_MSG_GLOBAL_REQUEST:
			case SSH_MSG_REQUEST_SUCCESS:
			case SSH_MSG_REQUEST_FAILURE:
			case SSH_MSG_CHANNEL_WINDOW_ADJUST:
			case SSH_MSG_CHANNEL_EXTENDED_DATA:
			case SSH_MSG_CHANNEL_SUCCESS:
			case SSH_MSG_CHANNEL_FAILURE:
			default:
				break;
		}

	}

clean_exit:

	msg_state->state = libssh2_NB_state_idle;

	return message;

new_message:
	// Discard this message and get a new one.
	msg_state->state = libssh2_NB_state_idle;
	goto next_message;

}

/*
 * _libssh2_message_get_channel
 *
 * Get a channel message packet from the brigade, format it into a 
 * LIBSSH2_MESSAGE structure and return it to the caller.
 * Returns LIBSSH2_MESSAGE on success, NULL on failure.
 *
 */
LIBSSH2_MESSAGE* _libssh2_message_get_channel(LIBSSH2_SERVER_SESSION* server,
											  LIBSSH2_CHANNEL* channel)
{
	message_processor_state_t*	msg_state;
	int					rc = 0, ret = 0;
	int					length;

	LIBSSH2_SESSION*	session;
	LIBSSH2_MESSAGE*	message;
	LIBSSH2_PACKET*		packet = NULL;

	if (!server || !channel)
		return NULL;

	session = server->session;
	msg_state = &server->msg_state;

	message = LIBSSH2_ALLOC(session, sizeof(LIBSSH2_MESSAGE));
	if (!message) {
		_libssh2_error(session, LIBSSH2_ERROR_ALLOC,
			"Unable to allocate space for message structure");
		return NULL;
	}
next_message:
	memset(message, 0, sizeof(LIBSSH2_MESSAGE));
	message->server = server;
	message->session = session;

	if (!message->channel_buf) {
		message->channel_buf = LIBSSH2_ALLOC(session, 
			session->open_channel->local.window_size);
		if (!message->channel_buf) {
					_libssh2_error(session, LIBSSH2_ERROR_ALLOC,
						"Unable to allocate space for channel buffer");
			return NULL;
		}
	}

	if (msg_state->state == libssh2_NB_state_idle) {

		message->channel_buf_len = libssh2_channel_read(channel,
			message->channel_buf, session->open_channel->local.window_size);

		message->msg_ptr = message->channel_buf;
		message->msg_len = message->channel_buf_len;
		message->type = message->channel_buf[0];
		message->offset = 1;

		msg_state->state = libssh2_NB_state_created;
	}

	if (msg_state->state == libssh2_NB_state_created) {
		// process channel message.

		switch(message->type) {
			case SSH_MSG_CHANNEL_OPEN:
				break;
			default:
				break;
		}

	}

clean_exit2:

	msg_state->state = libssh2_NB_state_idle;

	return message;

new_message2:
	// Discard this message and get a new one.
	msg_state->state = libssh2_NB_state_idle;
	goto next_message;

}

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
							  int success, char* resp_data)
{
    int rc;
	LIBSSH2_SESSION*			session;
	LIBSSH2_SERVER_SESSION*		server;

	server = message->server;
	session = message->session;

    BLOCK_ADJUST(rc, session, _libssh2_message_default_reply(message, 
		success, resp_data) );

    return rc;
}

/*
 * _libssh2_message_default_reply
 *
 * Get a service request packet from the brigade, format it into a 
 * LIBSSH2_MESSAGE structure and return it to the caller.
 * Returns LIBSSH2_MESSAGE on success, NULL on failure.
 *
 */
int _libssh2_message_default_reply(LIBSSH2_MESSAGE* message, 
								   int success, char* resp_data)
{
	message_processor_state_t*	msg_state;
	int				rc = -1, ret = 0, on = 1, off = 0;
	unsigned char*	s;
	unsigned char*	service = "service rejected";
    unsigned char*	r_packet = NULL;
    size_t			r_packet_len;
	LIBSSH2_SESSION*			session;
	LIBSSH2_SERVER_SESSION*		server;

	if (!message)
		return rc;

	server = message->server;
	session = message->session;
	msg_state = &server->msg_state;

	if (msg_state->state == libssh2_NB_state_idle) {

		switch(message->type) {
			case SSH_MSG_SERVICE_REQUEST:
				if (resp_data) service = resp_data;
				r_packet_len = 5 + strlen(service);
				s = r_packet = LIBSSH2_ALLOC(session, r_packet_len);
				*(s++) = SSH_MSG_SERVICE_ACCEPT;
				_libssh2_store_text(&s, service, strlen(service));
				break;
			case SSH_MSG_USERAUTH_REQUEST:
				r_packet_len = 1;
				if (resp_data) r_packet_len += 4 + strlen(resp_data);
				s = r_packet = LIBSSH2_ALLOC(session, r_packet_len + 1);
				if (success) {
					*(s++) = SSH_MSG_USERAUTH_SUCCESS;
					session->state |= LIBSSH2_STATE_AUTHENTICATED;
				} else
					*(s++) = SSH_MSG_USERAUTH_FAILURE;
				if (resp_data) {
					_libssh2_store_text(&s, resp_data, strlen(resp_data));
					r_packet_len++;
					*s = 0;
				}
				break;
			case SSH_MSG_CHANNEL_OPEN:
				r_packet_len = 1;
				if (message->msg_resp) r_packet_len += message->msg_resp_len;
				if (resp_data) r_packet_len += 4 + strlen(resp_data);
				s = r_packet = LIBSSH2_ALLOC(session, r_packet_len);
				if (success)
					*(s++) = SSH_MSG_CHANNEL_OPEN_CONFIRMATION;
				else
					*(s++) = SSH_MSG_CHANNEL_OPEN_FAILURE;
				if (message->msg_resp) {
					memcpy(s, message->msg_resp, message->msg_resp_len);
					s += message->msg_resp_len;
				}
				if (resp_data)
					_libssh2_store_text(&s, resp_data, strlen(resp_data));
				break;
			case SSH_MSG_CHANNEL_REQUEST:
				r_packet_len = 1;
				if (message->msg_resp) r_packet_len += message->msg_resp_len;
				if (resp_data) r_packet_len += 4 + strlen(resp_data);
				s = r_packet = LIBSSH2_ALLOC(session, r_packet_len);
				if (success)
					*(s++) = SSH_MSG_CHANNEL_SUCCESS;
				else
					*(s++) = SSH_MSG_CHANNEL_FAILURE;
				if (message->msg_resp) {
					memcpy(s, message->msg_resp, message->msg_resp_len);
					s += message->msg_resp_len;
				}
				if (resp_data)
					_libssh2_store_text(&s, resp_data, strlen(resp_data));
				ioctl(session->socket_fd, FIONBIO, (int*)&on);
				break;

// The following message types are not yet implemented
			case SSH_MSG_DISCONNECT:
			case SSH_MSG_IGNORE:
			case SSH_MSG_UNIMPLEMENTED:
			case SSH_MSG_DEBUG:
			case SSH_MSG_SERVICE_ACCEPT:
			case SSH_MSG_KEXINIT:
			case SSH_MSG_NEWKEYS:
			case SSH_MSG_USERAUTH_FAILURE:
			case SSH_MSG_USERAUTH_SUCCESS:
			case SSH_MSG_USERAUTH_BANNER:
			case SSH_MSG_USERAUTH_INFO_REQUEST:
			case SSH_MSG_USERAUTH_INFO_RESPONSE:
			case SSH_MSG_GLOBAL_REQUEST:
			case SSH_MSG_REQUEST_SUCCESS:
			case SSH_MSG_REQUEST_FAILURE:
			case SSH_MSG_CHANNEL_WINDOW_ADJUST:
			case SSH_MSG_CHANNEL_DATA:
			case SSH_MSG_CHANNEL_EXTENDED_DATA:
			case SSH_MSG_CHANNEL_EOF:
			case SSH_MSG_CHANNEL_CLOSE:

			default:
				break;
		}
		msg_state->state = libssh2_NB_state_created;
	}

	if (msg_state->state == libssh2_NB_state_created) {
		if (!r_packet) goto clean_exit;
        rc = _libssh2_transport_send(session, r_packet,
                                      r_packet_len,
									  NULL, 0);
        if (rc == LIBSSH2_ERROR_EAGAIN) {
			_libssh2_error(session, LIBSSH2_ERROR_EAGAIN,
				"Would block writing SFTP reply");
            return rc;
        } else if (rc) {
            ret = _libssh2_error(session, rc,
                                 "Unable to send reply message");
            goto clean_exit;
        }
	}

clean_exit:
	if (r_packet) LIBSSH2_FREE(session, r_packet);
	r_packet = NULL;

	msg_state->state = libssh2_NB_state_idle;

	return rc;
}


/*
 * libssh2_message_free
 *
 * Free storage for a LIBSSH2_MESSAGE.
 * Returns 0 on success, -1 on failure.
 *
 */
LIBSSH2_API int libssh2_message_free(LIBSSH2_MESSAGE* message)
{
	LIBSSH2_SERVER_SESSION*	server;
	LIBSSH2_SESSION*		session;
	unsigned char			*ptrnull;

	if (!message)
		return -1;

	server = message->server;
	session = message->session;

	if (message->msg_resp) {
		LIBSSH2_FREE(session, message->msg_resp);
		message->msg_resp = NULL;
	}

	if (message->channel_buf) {
		LIBSSH2_FREE(session, message->channel_buf);
		message->channel_buf = NULL;
	}

	LIBSSH2_FREE(session, message);

	return 0;
}

/*
 * libssh2_message_type
 *
 * Return the message type for the specified message.
 * Returns 0 on success, -1 on failure.
 *
 */
LIBSSH2_API int libssh2_message_type(LIBSSH2_MESSAGE* message)
{
	if (!message)
		return -1;
	return message->type;
}

/*
 * libssh2_message_parm
 *
 * Return the next parameter from the message.
 * Returns 0 on success, 1 on EOM, -1 on failure.
 *
 */
LIBSSH2_API int libssh2_message_parm(LIBSSH2_MESSAGE* message, char** parm, size_t* parmlen, int translate)
{
	int	rc = 1;		// Assume EOM.
	int len;

	if (!message)
		return -1;

	if (message->offset < message->msg_len) {
		*parmlen = _libssh2_ntohu32(message->msg_ptr + message->offset);
		*parm = message->msg_ptr + message->offset + 4;
#ifdef EBCDIC
		if (translate)
			libssh2_make_ebcdic(*parm, len);
#endif
		message->offset = message->offset + 4 + *parmlen;
		rc = 0;
	}

	return rc;
}

/*
 * libssh2_message_parm_text
 *
 * Return the next parameter from the message. The parameter is text and
 * will be translated as necessary.
 * Returns 0 on success, 1 on EOM, -1 on failure.
 *
 */
LIBSSH2_API int libssh2_message_parm_text(LIBSSH2_MESSAGE* message, char** parm, size_t* parmlen)
{
	int	rc = 1;		// Assume EOM.

	if (!message)
		return -1;

	if (message->offset < message->msg_len) {
		*parmlen = _libssh2_ntohu32(message->msg_ptr + message->offset);
		*parm = message->msg_ptr + message->offset + 4;
#ifdef EBCDIC
		libssh2_make_ebcdic(*parm, *parmlen);
#endif
		message->offset = message->offset + 4 + *parmlen;
		rc = 0;
	}

	return rc;
}

/*
 * libssh2_message_parm_str
 *
 * Return the next parameter from the message. The parameter is a string and
 * will not be translated.
 * Returns 0 on success, 1 on EOM, -1 on failure.
 *
 */
LIBSSH2_API int libssh2_message_parm_str(LIBSSH2_MESSAGE* message, char** parm, size_t* parmlen)
{
	int	rc = 1;		// Assume EOM.

	if (!message)
		return -1;

	if (message->offset < message->msg_len) {
		*parmlen = _libssh2_ntohu32(message->msg_ptr + message->offset);
		*parm = message->msg_ptr + message->offset + 4;
		message->offset = message->offset + 4 + *parmlen;
		rc = 0;
	}

	return rc;
}

/*
 * libssh2_message_parm_u32
 *
 * Return the next parameter from the message. The parameter is a 32-bit numeric.
 * Returns 0 on success, 1 on EOM, -1 on failure.
 *
 */
LIBSSH2_API int libssh2_message_parm_u32(LIBSSH2_MESSAGE* message, size_t* parm)
{
	int	rc = 1;		// Assume EOM.

	if (!message)
		return -1;

	if (message->offset < message->msg_len) {
		*parm = _libssh2_ntohu32(message->msg_ptr + message->offset);
		message->offset += 4;
		rc = 0;
	}

	return rc;
}

/*
 * libssh2_message_parm_u64
 *
 * Return the next parameter from the message. The parameter is a 64-bit numeric.
 * Returns 0 on success, 1 on EOM, -1 on failure.
 *
 */
LIBSSH2_API int libssh2_message_parm_u64(LIBSSH2_MESSAGE* message, libssh2_uint64_t* parm)
{
	int	rc = 1;		// Assume EOM.

	if (!message)
		return -1;

	if (message->offset < message->msg_len) {
		*parm = _libssh2_ntohu64(message->msg_ptr + message->offset);
		message->offset += 8;
		rc = 0;
	}

	return rc;
}

/*
 * libssh2_message_parm_bytes
 *
 * Return the next parameter from the message. The parameter is a series of bytes,
 * the length of which is specified in the parmlen parameter.
 * Returns 0 on success, 1 on EOM, -1 on failure.
 *
 */
LIBSSH2_API int libssh2_message_parm_bytes(LIBSSH2_MESSAGE* message, char** parm, size_t parmlen)
{
	int	rc = 1;		// Assume EOM.

	if (!message)
		return -1;

	if (message->offset < message->msg_len) {
		*parm = message->msg_ptr + message->offset;
		message->offset += parmlen;
		rc = 0;
	}

	return rc;
}

/*
 * libssh2_message_data_area
 *
 * Return the data area address created by the message processing routine.
 * Returns pointer on success, NULL on failure.
 *
 */
LIBSSH2_API void* libssh2_message_data_area(LIBSSH2_MESSAGE* message)
{
	return (void*)message->data_area;
}
