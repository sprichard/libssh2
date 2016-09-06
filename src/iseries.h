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


#ifndef ISERIES_H
#define ISERIES_H 1

#ifdef __OS400__

#define EBCDIC 1
#define CHARSET_EBCDIC 1

#include "libssh2_priv.h"
#include "ebcdic.h"
#include <string.h>
#include <strings.h>

/* Includes for iSeries functions */
#include <Qp0lstdi.h>
#include <quslfld.h>
#include <quscrtus.h>
#include <qusptrus.h>
#include <qusrobjd.h>
#include <qusgen.h>
#include <qusec.h>
#include <recio.h>
#include <signal.h>

/* Only do these defines if the program is not iseries.c */
#ifndef ISERIES_C
extern const char	*A2E, *E2A;
#endif

#if defined(__cplusplus) 
extern "C" { 
#endif 

unsigned long libssh2_clock(void);
#define LIBSSH2_CLOCKS_PER_SEC 1000000

void libssh2_make_ebcdic(char *data, int data_len);
void libssh2_make_ascii(char *data, int data_len);

int nuInitOpenSSL();
int nuFreeOpenSSL();

/*
int sshDBFOpenRead(LIBSSH2_SFTP_HANDLE *handle, char *ifsFileName);
int sshDBFOpenWrite(LIBSSH2_SFTP_HANDLE *handle, char *ifsFileName);
int sshDBFClose(LIBSSH2_SFTP_HANDLE *handle);
int sshDBFRead(LIBSSH2_SFTP_HANDLE *handle, char* buffer, int buffer_len);
int sshDBFWrite(LIBSSH2_SFTP_HANDLE *handle, char* buffer, int buffer_len);
*/

int file_read_publickey_TBSI(LIBSSH2_SESSION* session,
					unsigned char **method,
                    size_t *method_len,
                    unsigned char **pubkeydata,
                    size_t *pubkeydata_len,
                    const char *pubkeyfile);

int file_read_publickey_ZMOD(LIBSSH2_SESSION* session,
					unsigned char **method,
                    size_t *method_len,
                    unsigned char **pubkeydata,
                    size_t *pubkeydata_len,
                    const char *pubkeyfile);

int file_read_privatekey_ZMOD(LIBSSH2_SESSION * session,
                    unsigned char **privkeydata,
                    size_t *privkeydata_len,
                    const char *privkeyfile);

#if defined(__cplusplus) 
} 
#endif 

#endif /* __OS400__ */

#endif /* ISERIES_H */
