#ifndef __LIBSSH2_SERVER_H
#define __LIBSSH2_SERVER_H

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

#ifdef HAVE_WINDOWS_H
# include <windows.h>
#endif
#ifdef HAVE_WINSOCK2_H
# include <winsock2.h>
#endif
#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif
# ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
# ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#define LIBSSH2_KEYTYPE_RSA	1
#define LIBSSH2_KEYTYPE_DSS	2

/*
 * _libssh2_server_startup
 *
 * Perform key exchange. Trade banners, exchange keys, setup crypto, 
 * compression and MAC layers.
 * Returns LIBSSH2_SERVER_SESSION on success, NULL on failure.
 *
 */
int _libssh2_server_startup(LIBSSH2_SERVER_SESSION* session);

/*
 * _libssh2_server_get_message
 *
 * Get SSH message from client.
 * Returns LIBSSH2_SERVER_MESSAGE on success, NULL on failure.
 *
 */
LIBSSH2_MESSAGE* _libssh2_server_get_message(LIBSSH2_SERVER_SESSION* session);

/*
 * _libssh2_server_disconnect
 *
 * Disconnect server session.
 * Returns 0 on success, non-zero on failure.
 *
 */
int _libssh2_server_disconnect(LIBSSH2_SERVER_SESSION* server_session);


#endif /* __LIBSSH2_SERVER_H */
