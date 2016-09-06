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
 * This file handles the creation of libssh2 server-side support.
 */

#include "libssh2_priv.h"
#include <errno.h>
#include <fcntl.h>
#include <assert.h>
#include "server.h"
#include "session.h"
#include "misc.h"

/*
 * libssh2_server_init
 *
 * Initialize Server instance.
 * Returns LIBSSH2_SERVER on success, NULL on failure.
 *
 */
LIBSSH2_SERVER* libssh2_server_init(unsigned long ipAddr, int portNum,
				char* pubkeyfile, char* privkeyfile)
{
	LIBSSH2_SERVER *server;
	unsigned char *pubkeydata = NULL;
	unsigned char *privkeydata = NULL;
	size_t pubkeydata_len = 0;
	size_t privkeydata_len = 0;
	int rc;

	server = malloc(sizeof(LIBSSH2_SERVER));
	if (server) {
		memset(server, 0, sizeof(LIBSSH2_SERVER));
		server->ipAddr = ipAddr;
		server->portNum = portNum;
		strcpy(server->pubkeyfile, pubkeyfile);
		strcpy(server->privkeyfile, privkeyfile);
		server->session = libssh2_session_init();
		if (!server->session) {
			_libssh2_error(server->session, LIBSSH2_ERROR_ALLOC,
				"Unable to initialize SSH2 session.");
			free(server);
			server = NULL;
			return NULL;
		}
#ifdef __OS400__
		nuInitOpenSSL();
		rc = file_read_publickey_TBSI(server->session, &server->keyTypeName,
#else
		rc = file_read_publickey(server->session, &server->keyTypeName,
#endif
			&server->keyTypeLen, &pubkeydata, &pubkeydata_len, pubkeyfile);
		
		if(rc) {
			_libssh2_error(server->session, LIBSSH2_ERROR_ALLOC,
				"Unable to read public key file.");
			free(server);
			server = NULL;
			return NULL;
		}
		server->pubkey = pubkeydata;
		server->pubkeylen = pubkeydata_len;
	}
	return server;
}

/*
 * libssh2_server_shutdown
 *
 * Shutdown Server instance.
 * Returns 0 on success, non-zero on failure.
 *
 */
int libssh2_server_shutdown(LIBSSH2_SERVER* server)
{
	// Close listen socket.
	close(server->sock);

	free(server);

	return 0;
}

/*
 * libssh2_server_listen
 *
 * Listen for an incoming connect.
 * Returns 0 on success, non-zero on failure.
 *
 */
int libssh2_server_listen(LIBSSH2_SERVER* server)
{
	LIBSSH2_SERVER* srv;
	int opt = 1;

	srv = server;

	if (!srv->sock) {
		// Acquire/bind socket
		srv->sock = socket(AF_INET, SOCK_STREAM, 0);
		if (srv->sock == -1) {
			_libssh2_error(srv->session, LIBSSH2_ERROR_SOCKET_NONE,
                      "Error acquiring socket");
			srv->sock = 0;
			memset((void*)&srv->sin, 0, sizeof(struct sockaddr_in));
			return LIBSSH2_ERROR_SOCKET_NONE;
		}
		srv->sin.sin_addr.s_addr = srv->ipAddr;
		srv->sin.sin_family = AF_INET;
		srv->sin.sin_port = htons(srv->portNum);
		if (setsockopt(srv->sock, SOL_SOCKET, SO_REUSEADDR,
                   (char *)&opt, sizeof(opt)) < 0) {
			_libssh2_error(srv->session, LIBSSH2_ERROR_SOCKET_NONE,
				"Error on setsockopt.");
			close(srv->sock);
			srv->sock = 0;
			memset((void*)&srv->sin, 0, sizeof(struct sockaddr_in));
			return LIBSSH2_ERROR_SOCKET_NONE;
		}
//		if (bind(srv->sock, (struct sockaddr*)(&srv->sin),
		if (bind(srv->sock, (struct sockaddr*)&srv->sin,
                sizeof(struct sockaddr_in)) != 0) {
			_libssh2_error(srv->session, LIBSSH2_ERROR_SOCKET_NONE,
				"Failed to bind socket.");
			close(srv->sock);
			srv->sock = 0;
			memset((void*)&srv->sin, 0, sizeof(struct sockaddr_in));
			return LIBSSH2_ERROR_SOCKET_NONE;
		}
	}
	if (listen(srv->sock, 10) < 0) {
		_libssh2_error(srv->session, LIBSSH2_ERROR_SOCKET_NONE,
			"Listen on socket failed.");
		close(srv->sock);
		srv->sock = 0;
		memset((void*)&srv->sin, 0, sizeof(struct sockaddr_in));
		return LIBSSH2_ERROR_SOCKET_NONE;
	}
	return 0;
}

/*
 * libssh2_server_accept
 *
 * Accept an incoming connection.
 * Returns LIBSSH2_SESSION on success, NULL on failure.
 *
 */
LIBSSH2_SERVER_SESSION* libssh2_server_accept(LIBSSH2_SERVER* server)
{
	int rc = 0;
	LIBSSH2_SERVER_SESSION *s;

//	if (server->dsakey == NULL && server->rsakey == NULL) {
//		libssh2_error(session, LIBSSH2_ERROR_SOCKET_NONE,
//			"DSA or RSA host key file must be set before accept().", 0);
//	}

	s = malloc(sizeof(LIBSSH2_SERVER_SESSION));
	if (s) {
		memset(s, 0, sizeof(LIBSSH2_SERVER_SESSION));
		s->server = server;
		// Establish SSH Session.
		s->session = libssh2_session_init();
		if (!s->session) {
			_libssh2_error(s->session, LIBSSH2_ERROR_ALLOC,
				"Unable to initialize SSH2 session.");
			free(s);
			s = NULL;
			return s;
		}
		s->session->server = s;
		strcpy(s->pubkeyfile, server->pubkeyfile);
		strcpy(s->privkeyfile, server->privkeyfile);
		s->pubkey = server->pubkey;
		s->pubkeylen = server->pubkeylen;
		s->privkey = server->privkey;
		s->privkeylen = server->privkeylen;
		s->session->server_hostkey = s->pubkey;
		s->session->server_hostkey_len = s->pubkeylen;
		s->sock = accept(server->sock, NULL, NULL);
		if (s->sock == -1) {
			_libssh2_error(s->session, LIBSSH2_ERROR_SOCKET_NONE,
				"Unable to accept new connection.");
			free(s);
			s = NULL;
			return s;
		}

		s->version = 2;
	}
	return s;
}

/*
 * libssh2_server_accept_socket
 *
 * Set up session blocks for previously accepted socket.
 * Returns LIBSSH2_SESSION on success, NULL on failure.
 *
 */
LIBSSH2_SERVER_SESSION* libssh2_server_accept_socket(LIBSSH2_SERVER* server, int sock)
{
	int rc = 0;
	LIBSSH2_SERVER_SESSION *s = NULL;

	if (sock < 0) {
			return NULL;
	}

//	if (server->dsakey == NULL && server->rsakey == NULL) {
//		libssh2_error(session, LIBSSH2_ERROR_SOCKET_NONE,
//			"DSA or RSA host key file must be set before accept().", 0);
//	}

	s = malloc(sizeof(LIBSSH2_SERVER_SESSION));
	if (s) {
		memset(s, 0, sizeof(LIBSSH2_SERVER_SESSION));
		s->sock = sock;
		s->server = server;
		// Establish SSH Session.
		s->session = libssh2_session_init();
		if (!s->session) {
			_libssh2_error(s->session, LIBSSH2_ERROR_ALLOC,
				"Unable to initialize SSH2 session.");
			free(s);
			s = NULL;
			return s;
		}
		s->session->server = s;
		strcpy(s->pubkeyfile, server->pubkeyfile);
		strcpy(s->privkeyfile, server->privkeyfile);
		s->pubkey = server->pubkey;
		s->pubkeylen = server->pubkeylen;
		s->privkey = server->privkey;
		s->privkeylen = server->privkeylen;
		s->session->server_hostkey = s->pubkey;
		s->session->server_hostkey_len = s->pubkeylen;
		s->version = 2;
	}
	return s;
}

/*
 * proto libssh2_server_startup
 *
 * server: LIBSSH2_SESSION struct allocated and owned by the calling program
 * Returns: 0 on success, or non-zero on failure
 * Any memory allocated by libssh2 will use alloc/realloc/free
 * callbacks in session.
 */
LIBSSH2_API int
libssh2_server_startup(LIBSSH2_SERVER_SESSION* server)
{
    int rc;

    BLOCK_ADJUST(rc, server->session, _libssh2_server_startup(server) );

    return rc;
}

/*
 * _libssh2_server_startup
 *
 * Perform key exchange. Trade banners, exchange keys, setup crypto, 
 * compression and MAC layers.
 * Returns 0 on success, non-zero on failure.
 *
 */
int _libssh2_server_startup(LIBSSH2_SERVER_SESSION* server_session)
{
	LIBSSH2_SERVER_SESSION* ss;
	LIBSSH2_SESSION* session;
	int rc;

	ss = server_session;
	session = ss->session;

#ifdef __OS400__
	nuInitOpenSSL();
#endif

    if (session->startup_state == libssh2_NB_state_idle) {
	
	    /* FIXME: on some platforms (like win32) sockets are unsigned */
		session->socket_fd = ss->sock;

		_libssh2_debug(session, LIBSSH2_TRACE_TRANS,
			"session_startup for socket %d", session->socket_fd);

		libssh2_session_set_blocking(session, 1);

        session->startup_state = libssh2_NB_state_created;
    }

    if (session->startup_state == libssh2_NB_state_created) {
        rc = banner_send(session);
        if (rc == LIBSSH2_ERROR_EAGAIN) {
            _libssh2_error(session, LIBSSH2_ERROR_EAGAIN,
                          "Would block sending banner to remote host");
            return LIBSSH2_ERROR_EAGAIN;
        } else if (rc) {
            /* Unable to send banner? */
            _libssh2_error(session, LIBSSH2_ERROR_BANNER_SEND,
                          "Error sending banner to remote host");
            return LIBSSH2_ERROR_BANNER_SEND;
        }
        session->startup_state = libssh2_NB_state_sent;
    }

    if (session->startup_state == libssh2_NB_state_sent) {
        rc = banner_receive(session);
        if (rc == LIBSSH2_ERROR_EAGAIN) {
            _libssh2_error(session, LIBSSH2_ERROR_EAGAIN,
                          "Would block waiting for banner");
            return LIBSSH2_ERROR_EAGAIN;
        } else if (rc) {
            /* Unable to receive banner from remote */
            _libssh2_error(session, LIBSSH2_ERROR_BANNER_NONE,
                          "Timeout waiting for banner");
            return LIBSSH2_ERROR_BANNER_NONE;
        }
        session->startup_state = libssh2_NB_state_sent1;
    }

    if (session->startup_state == libssh2_NB_state_sent1) {
        rc = _libssh2_server_kex_exchange(ss, 0, &session->startup_key_state);
        if (rc == LIBSSH2_ERROR_EAGAIN) {
            _libssh2_error(session, LIBSSH2_ERROR_EAGAIN,
                          "Would block exchanging encryption keys");
            return LIBSSH2_ERROR_EAGAIN;
        } else if (rc) {
            _libssh2_error(session, LIBSSH2_ERROR_KEX_FAILURE,
                          "Unable to exchange encryption keys");
            return LIBSSH2_ERROR_KEX_FAILURE;
        }

        session->startup_state = libssh2_NB_state_sent2;
    }

	session->startup_state = libssh2_NB_state_idle;
	return 0;
}

/*
 * proto libssh2_server_disconnect
 *
 * server: LIBSSH2_SESSION struct allocated and owned by the calling program
 * Returns: 0 on success, or non-zero on failure
 * Any memory allocated by libssh2 will use alloc/realloc/free
 * callbacks in session.
 */
LIBSSH2_API int
libssh2_server_disconnect(LIBSSH2_SERVER_SESSION* server)
{
    int rc;

    BLOCK_ADJUST(rc, server->session, _libssh2_server_disconnect(server) );

    return rc;
}

/*
 * _libssh2_server_disconnect
 *
 * Disconnect server session.
 * Returns 0 on success, non-zero on failure.
 *
 */
int _libssh2_server_disconnect(LIBSSH2_SERVER_SESSION* server_session)
{
	LIBSSH2_SERVER_SESSION* ss;
	LIBSSH2_SESSION* session;
	int rc;

	ss = server_session;
	session = ss->session;

	close(session->socket_fd);

    libssh2_session_free(session);

	free(ss);

	return 0;
}

/*
 * libssh2_server_get_remote_banner
 *
 * Return pointer to the client's banner.
 * Returns banner pointer on success, NULL on failure.
 *
 */
LIBSSH2_API char*
libssh2_server_get_remote_banner(LIBSSH2_SERVER_SESSION* server)
{
	LIBSSH2_SESSION* session;

	if (!server) return NULL;
	session = server->session;

	return (char*)libssh2_session_banner_get(session);

}

/* Keep-alive stuff for servers. */

LIBSSH2_API void
libssh2_server_keepalive_config (LIBSSH2_SERVER_SESSION *server,
                          int want_reply,
                          unsigned interval)
{
	LIBSSH2_SESSION* session;

	if (!server) return;
	session = server->session;
	if (!session) return;

	libssh2_keepalive_config(session, want_reply, interval);
	return;

}

/* libssh2_server_last_error
 *
 * Returns error code and populates an error string into errmsg If want_buf is
 * non-zero then the string placed into errmsg must be freed by the calling
 * program. Otherwise it is assumed to be owned by libssh2
 */
LIBSSH2_API int
libssh2_server_last_error(LIBSSH2_SERVER_SESSION *server, char **errmsg,
                           int *errmsg_len, int want_buf)
{
	LIBSSH2_SESSION* session;

	if (!server) return -1;
	session = server->session;
	if (!session) return -1;

	return libssh2_session_last_error(session, errmsg, errmsg_len, want_buf);

}
