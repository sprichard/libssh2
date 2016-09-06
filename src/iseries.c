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
 
#define ISERIES_C

#include "libssh2_priv.h"
#include "iseries.h"

#ifdef __OS400__

#include <stdlib.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>
#include <QUSEC.h>
#include <QC3PRNG.h>
#include "openssl/err.h" 
#include "openssl/evp.h" 
#include "openssl/hmac.h" 
#include "openssl/x509.h" 
#include "openssl/blowfish.h" 

#include <pthread.h>
#include <iconv.h>

struct timeval	libssh2_timeval;
struct timeval	*libssh2_tvp = NULL;

int			icInit = 0;
iconv_t		icAtoE;
iconv_t		icEtoA;

char		*CCS819 = "IBMCCSID008190000000000000000000";
char		*CCS037 = "IBMCCSID000370000000000000000000";

/*
This code does basic character mapping for IBM's TPF and OS/390 operating systems.
It is a modified version of the BS2000 table.

Bijective EBCDIC (character set IBM-1047) to US-ASCII table:
This table is bijective - there are no ambigous or duplicate characters.
*/
const unsigned char ssh_ascii_table[256] = {
    0x00, 0x01, 0x02, 0x03, 0x85, 0x09, 0x86, 0x7f, /* 00-0f:           */
    0x87, 0x8d, 0x8e, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, /* ................ */
    0x10, 0x11, 0x12, 0x13, 0x8f, 0x0a, 0x08, 0x97, /* 10-1f:           */
    0x18, 0x19, 0x9c, 0x9d, 0x1c, 0x1d, 0x1e, 0x1f, /* ................ */
    0x80, 0x81, 0x82, 0x83, 0x84, 0x92, 0x17, 0x1b, /* 20-2f:           */
    0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x05, 0x06, 0x07, /* ................ */
    0x90, 0x91, 0x16, 0x93, 0x94, 0x95, 0x96, 0x04, /* 30-3f:           */
    0x98, 0x99, 0x9a, 0x9b, 0x14, 0x15, 0x9e, 0x1a, /* ................ */
    0x20, 0xa0, 0xe2, 0xe4, 0xe0, 0xe1, 0xe3, 0xe5, /* 40-4f:           */
    0xe7, 0xf1, 0xa2, 0x2e, 0x3c, 0x28, 0x2b, 0x7c, /*  ...........<(+| */
    0x26, 0xe9, 0xea, 0xeb, 0xe8, 0xed, 0xee, 0xef, /* 50-5f:           */
    0xec, 0xdf, 0x21, 0x24, 0x2a, 0x29, 0x3b, 0x5e, /* &.........!$*);^ */
    0x2d, 0x2f, 0xc2, 0xc4, 0xc0, 0xc1, 0xc3, 0xc5, /* 60-6f:           */
    0xc7, 0xd1, 0xa6, 0x2c, 0x25, 0x5f, 0x3e, 0x3f, /* -/.........,%_>? */
    0xf8, 0xc9, 0xca, 0xcb, 0xc8, 0xcd, 0xce, 0xcf, /* 70-7f:           */
    0xcc, 0x60, 0x3a, 0x23, 0x40, 0x27, 0x3d, 0x22, /* .........`:#@'=" */
    0xd8, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, /* 80-8f:           */
    0x68, 0x69, 0xab, 0xbb, 0xf0, 0xfd, 0xfe, 0xb1, /* .abcdefghi...... */
    0xb0, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, /* 90-9f:           */
    0x71, 0x72, 0xaa, 0xba, 0xe6, 0xb8, 0xc6, 0xa4, /* .jklmnopqr...... */
    0xb5, 0x7e, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, /* a0-af:           */
    0x79, 0x7a, 0xa1, 0xbf, 0xd0, 0x5b, 0xde, 0xae, /* .~stuvwxyz...[.. */
    0xac, 0xa3, 0xa5, 0xb7, 0xa9, 0xa7, 0xb6, 0xbc, /* b0-bf:           */
    0xbd, 0xbe, 0xdd, 0xa8, 0xaf, 0x5d, 0xb4, 0xd7, /* .............].. */
    0x7b, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, /* c0-cf:           */
    0x48, 0x49, 0xad, 0xf4, 0xf6, 0xf2, 0xf3, 0xf5, /* {ABCDEFGHI...... */
    0x7d, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, /* d0-df:           */
    0x51, 0x52, 0xb9, 0xfb, 0xfc, 0xf9, 0xfa, 0xff, /* }JKLMNOPQR...... */
    0x5c, 0xf7, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, /* e0-ef:           */
    0x59, 0x5a, 0xb2, 0xd4, 0xd6, 0xd2, 0xd3, 0xd5, /* \.STUVWXYZ...... */
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, /* f0-ff:           */
    0x38, 0x39, 0xb3, 0xdb, 0xdc, 0xd9, 0xda, 0x9f  /* 0123456789...... */
};


/*
The US-ASCII to EBCDIC (character set IBM-1047) table:
This table is bijective (no ambiguous or duplicate characters)
*/
const unsigned char ssh_ebcdic_table[256] = {
    0x00, 0x01, 0x02, 0x03, 0x37, 0x2d, 0x2e, 0x2f, /* 00-0f:           */
    0x16, 0x05, 0x15, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, /* ................ */
    0x10, 0x11, 0x12, 0x13, 0x3c, 0x3d, 0x32, 0x26, /* 10-1f:           */
    0x18, 0x19, 0x3f, 0x27, 0x1c, 0x1d, 0x1e, 0x1f, /* ................ */
    0x40, 0x5a, 0x7f, 0x7b, 0x5b, 0x6c, 0x50, 0x7d, /* 20-2f:           */
    0x4d, 0x5d, 0x5c, 0x4e, 0x6b, 0x60, 0x4b, 0x61, /*  !"#$%&'()*+,-./ */
    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, /* 30-3f:           */
    0xf8, 0xf9, 0x7a, 0x5e, 0x4c, 0x7e, 0x6e, 0x6f, /* 0123456789:;<=>? */
    0x7c, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, /* 40-4f:           */
    0xc8, 0xc9, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, /* @ABCDEFGHIJKLMNO */
    0xd7, 0xd8, 0xd9, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, /* 50-5f:           */
    0xe7, 0xe8, 0xe9, 0xad, 0xe0, 0xbd, 0x5f, 0x6d, /* PQRSTUVWXYZ[\]^_ */
    0x79, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, /* 60-6f:           */
    0x88, 0x89, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, /* `abcdefghijklmno */
    0x97, 0x98, 0x99, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, /* 70-7f:           */
    0xa7, 0xa8, 0xa9, 0xc0, 0x4f, 0xd0, 0xa1, 0x07, /* pqrstuvwxyz{|}~. */
    0x20, 0x21, 0x22, 0x23, 0x24, 0x04, 0x06, 0x08, /* 80-8f:           */
    0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x09, 0x0a, 0x14, /* ................ */
    0x30, 0x31, 0x25, 0x33, 0x34, 0x35, 0x36, 0x17, /* 90-9f:           */
    0x38, 0x39, 0x3a, 0x3b, 0x1a, 0x1b, 0x3e, 0xff, /* ................ */
    0x41, 0xaa, 0x4a, 0xb1, 0x9f, 0xb2, 0x6a, 0xb5, /* a0-af:           */
    0xbb, 0xb4, 0x9a, 0x8a, 0xb0, 0xca, 0xaf, 0xbc, /* ................ */
    0x90, 0x8f, 0xea, 0xfa, 0xbe, 0xa0, 0xb6, 0xb3, /* b0-bf:           */
    0x9d, 0xda, 0x9b, 0x8b, 0xb7, 0xb8, 0xb9, 0xab, /* ................ */
    0x64, 0x65, 0x62, 0x66, 0x63, 0x67, 0x9e, 0x68, /* c0-cf:           */
    0x74, 0x71, 0x72, 0x73, 0x78, 0x75, 0x76, 0x77, /* ................ */
    0xac, 0x69, 0xed, 0xee, 0xeb, 0xef, 0xec, 0xbf, /* d0-df:           */
    0x80, 0xfd, 0xfe, 0xfb, 0xfc, 0xba, 0xae, 0x59, /* ................ */
    0x44, 0x45, 0x42, 0x46, 0x43, 0x47, 0x9c, 0x48, /* e0-ef:           */
    0x54, 0x51, 0x52, 0x53, 0x58, 0x55, 0x56, 0x57, /* ................ */
    0x8c, 0x49, 0xcd, 0xce, 0xcb, 0xcf, 0xcc, 0xe1, /* f0-ff:           */
    0x70, 0xdd, 0xde, 0xdb, 0xdc, 0x8d, 0x8e, 0xdf  /* ................ */
};

const char	*A2E = ssh_ebcdic_table;
const char	*E2A = ssh_ascii_table;

/*
 * Prototypes for static functions
 */
static int PrepareThreads(void);
static void CleanupThreads(void);
static void LockingCallback(int mode, int type, const char* file, int line);
static unsigned long ThreadIDCallback();
// int file_read_publickey_TBSI(LIBSSH2_SESSION * session,
//					unsigned char **method,
//                    size_t *method_len,
//                    unsigned char **pubkeydata,
//                    size_t *pubkeydata_len,
//                    const char *pubkeyfile);

/*
 * Static variables for thread safety
 *
 * NOTE!!! Multi-threaded programs should make an explicit call
 * to B_CreateSessionChooser before creating any threads.  Make
 * an explicit call to B_FreeSessionChooser after all threads finish.
 * This ensures proper, and unique, initialization/release of mutexes
 * and OpenSSL algorithms.
 */
static int				opensslInitialized = 0;
static pthread_mutex_t*	mutexArray;

/*
 * make_ebcdic
 *
 * Convert ASCII to EBCDIC
 */
LIBSSH2_API void libssh2_set_translate_tables(char *a2e, char *e2a)
{

	if (a2e) A2E = a2e;
	if (e2a) E2A = e2a;

	return;

}

/*
 * make_ebcdic
 *
 * Convert ASCII to EBCDIC
 */
void libssh2_make_ebcdic(char *data, int data_len)
{
	int		i;

	for(i = 0; i<data_len; i++) {
		data[i] = A2E[data[i]];
	}

    return;
}


/*
 * make_ebcdic
 *
 * Convert ASCII to EBCDIC
 */
void libssh2_make_ascii(char *data, int data_len)
{
	int		i;

	for(i = 0; i<data_len; i++) {
		data[i] = E2A[data[i]];
	}

    return;
}

/*
 * Initialize OpenSSL
 * See note above about multi-threaded programs.
 */
int nuInitOpenSSL()
{
    int			rc = 0;
    Qus_EC_t	ERRC0100;
	char		workBuf[256];
    if (opensslInitialized == 0) {
        /* Go create the mutexes needed for threadsafe crypto */
        rc = PrepareThreads();
        /* Load the error text strings */
        ERR_load_crypto_strings();
        /* Add all algorithms */
        OpenSSL_add_all_algorithms();
		do {
			/* Generate random value */
			memset(&ERRC0100, 0, sizeof(ERRC0100));
			ERRC0100.Bytes_Provided = sizeof(ERRC0100);
			Qc3GenPRNs(workBuf, sizeof(workBuf), '0', '0', &ERRC0100);
			if (ERRC0100.Bytes_Available != 0) {
				rc = 3104;  /* PRNG failure */
				return rc;
			}
			RAND_seed(workBuf, sizeof(workBuf));
		} while(!RAND_status());

        opensslInitialized = 1;
    }
    return rc;
}

/*
 * Finalize the BSAFEBRIDGE
 * See note above about multi-threaded programs.
 */
int nuFreeOpenSSL()
{
/* We no longer free the resources held by OpenSSL messages, algorithms,
   and threads.  This is because we were spending too much time loading
   and unloading these things whenever the SDK is used to do a lot of 
   simple, self-contained functions; e.g., hashing.  At the start of the
   hash, B_CreateAlgorithmObject would initialize OpenSSL.  At the end of the
   hash, B_DestroyAlgorithmObject would free OpenSSL resources.  When the hash
   function was called repeatedly, we saw a serious performance impact.
   We now initialize OpenSSL on the first B_CreateAlgorithmObject, or any
   other place that invokes the INITIALIZE_BRIDGE macro, and we never free
   the resources.  We rely on the operating system to clean up after us
   when we are unloaded.

    if (--referenceCount == 0) {
        ERR_free_strings();
        EVP_cleanup();
        CleanupThreads();
    }
    else if (referenceCount < 0) {
        referenceCount = 0;
    }
*/
    return 0;
}

/*
 * Setup mutexes required by OpenSSL for thread safety
 */
static int
PrepareThreads()
{
    int i;
    int lockCount = CRYPTO_num_locks();

#if 0
    printf("Preparing OpenSSL for threads\n");
    fflush(stdout);
#endif

    /* Allocate array of mutexes */
	mutexArray = (pthread_mutex_t*)malloc(lockCount * sizeof(pthread_mutex_t));

	if (!mutexArray) {
		printf("Unable to allocate memory for mutex array\n");
		return -1;
	}

    /* Create the mutexes */
    for (i = 0; i < lockCount; ++i) {
        if (pthread_mutex_init(&mutexArray[i], NULL) != 0) {
            return -1;
        }
    }
    CRYPTO_set_locking_callback(LockingCallback);

    CRYPTO_set_id_callback(ThreadIDCallback);

	return 0;
}

/*
 * Free mutexes used by OpenSSL for thread safety
 */
static void
CleanupThreads()
{
    int i;
    int lockCount = CRYPTO_num_locks();

#if 0
    printf("Cleaning up OpenSSL threads\n");
    fflush(stdout);
#endif

    CRYPTO_set_locking_callback(NULL);

    CRYPTO_set_id_callback(NULL);

    for (i = 0; i < lockCount; ++i) {
        pthread_mutex_destroy(&mutexArray[i]);
    }
    free(mutexArray);
}

/*
 * Callback used by OpenSSL to lock/unlock a mutex
 */
static void
LockingCallback(int mode, int type, const char* file, int line)
{
#if 0
    printf("LockingCallback mode: %s, type: %u, file: %s, line: %u\n",
        mode & CRYPTO_LOCK ? "LOCK" : "UNLOCK", type, file, line);
    fflush(stdout);
#endif

    if (mode & CRYPTO_LOCK) {
        pthread_mutex_lock(&mutexArray[type]);
    }
    else {
        pthread_mutex_unlock(&mutexArray[type]);
    }
}

/*
 * Callback used by OpenSSL to get unique thread ID
 */
static unsigned long
ThreadIDCallback()
{
    unsigned long id;

    pthread_t tID;
    tID = pthread_self();
    id = *(unsigned long*)&tID;

#if 0
    printf("ThreadIDCallback for thread: %u\n", id);
    fflush(stdout);
#endif

    return id;
}

/*
 * file_read_publickey_TBSI
 *
 * Read a public key from an id_???.pub style file
 * generated by Trailblazer Systems Inc. key generator
 *
 * Returns an allocated string in *pubkeydata on success.
 */
int file_read_publickey_TBSI(LIBSSH2_SESSION * session,
					unsigned char **method,
                    size_t *method_len,
                    unsigned char **pubkeydata,
                    size_t *pubkeydata_len,
                    const char *pubkeyfile)
{
    FILE *fd;
    char c;
	char buffer[16384];
    unsigned char *pubkey = NULL, *tmp, *pubkeyptr = NULL;
    size_t pubkey_len = 0;
    unsigned int tmp_len;
	int		rc;
	char*	ptr;

    _libssh2_debug(session, LIBSSH2_TRACE_AUTH, "Loading public key file: %s",
                   pubkeyfile);
    /* Read Public Key */
    fd = fopen(pubkeyfile, "r");
    if (!fd) {
        _libssh2_error(session, LIBSSH2_ERROR_FILE,
                      "Unable to open public key file");
        return -1;
    }
	pubkey = LIBSSH2_ALLOC(session, 8192);
	do {
		if ((ptr = fgets(buffer, sizeof(buffer), fd)) == NULL) {
			if (fd)
				break;
			_libssh2_error(session, LIBSSH2_ERROR_FILE,
                      "Unable to open public key file");
			LIBSSH2_FREE(session, pubkey);
			return -1;
		}
		do {
			if (buffer[strlen(buffer)-1] == '\r' || 
				buffer[strlen(buffer)-1] == '\n' ||
				buffer[strlen(buffer)-1] == 0x25) {
				buffer[strlen(buffer)-1] = '\0';
				continue;
			}
			break;
		} while(1);
		if (!strcmp(buffer, "---- BEGIN SSH2 PUBLIC KEY ----"))
			continue;
		if (!memcmp(buffer, "Comment: ", 9)) {
			if (!memcmp((char*)&buffer[10], "rsa-key", 7)) {
				strcpy(pubkey, "ssh-rsa ");
				*method = pubkey;
				*method_len = 7;
				pubkeyptr = pubkey + 7;
			}
			if (!memcmp((char*)&buffer[10], "dsa-key", 7)) {
				strcpy(pubkey, "ssh-dsa ");
				*method = pubkey;
				*method_len = 7;
				pubkeyptr = pubkey + 7;
			}
			continue;
		}
		if (!strcmp(buffer, "---- END SSH2 PUBLIC KEY ----"))
			break;
		strcat(pubkey, buffer);
	} while(1);
	fclose(fd);

	if (!pubkeyptr) {
		_libssh2_error(session, LIBSSH2_ERROR_FILE,
                      "Invalid key data, unknown key type");
        LIBSSH2_FREE(session, pubkey);
        return -1;
	}

    if (libssh2_base64_decode(session, (char **) &tmp, &tmp_len,
                              (char *) pubkeyptr, strlen(pubkeyptr))) {
        _libssh2_error(session, LIBSSH2_ERROR_FILE,
                      "Invalid key data, not base64 encoded");
        LIBSSH2_FREE(session, pubkey);
        return -1;
    }
    *pubkeydata = tmp;
    *pubkeydata_len = tmp_len;

    return 0;
}

/*
 * file_read_publickey_ZMOD
 *
 * Read a public key from a ZMOD_SSH_Key.pub file
 * generated by ZGENSSHKEY key generator
 *
 * Returns an allocated string in *pubkeydata on success.
 */
int file_read_publickey_ZMOD(LIBSSH2_SESSION * session,
					unsigned char **method,
                    size_t *method_len,
                    unsigned char **pubkeydata,
                    size_t *pubkeydata_len,
                    const char *pubkeyfile)
{
    FILE *fd;
    char c;
	char buffer[16384];
    unsigned char *pubkey = NULL, *tmp, *pubkeyptr = NULL;
    size_t pubkey_len = 0;
    unsigned int tmp_len;
	int		rc;
	char*	ptr;

    _libssh2_debug(session, LIBSSH2_TRACE_AUTH, "Loading public key file: %s",
                   pubkeyfile);
    /* Read Public Key */
    fd = fopen(pubkeyfile, "r");
    if (!fd) {
        _libssh2_error(session, LIBSSH2_ERROR_FILE,
                      "Unable to open public key file");
        return -1;
    }
	pubkey = LIBSSH2_ALLOC(session, 8192);
	do {
		if ((ptr = fgets(buffer, sizeof(buffer), fd)) == NULL) {
			if (fd)
				break;
			_libssh2_error(session, LIBSSH2_ERROR_FILE,
                      "Unable to read public key file");
			LIBSSH2_FREE(session, pubkey);
			return -1;
		}
		do {
			if (buffer[strlen(buffer)-1] == '\r' || 
				buffer[strlen(buffer)-1] == '\n' ||
				buffer[strlen(buffer)-1] == 0x25) {
				buffer[strlen(buffer)-1] = '\0';
				continue;
			}
			break;
		} while(1);
		if (!strcmp(buffer, "---- BEGIN SSH2 PUBLIC KEY ----"))
			continue;
		if (!memcmp(buffer, "Subject: ", 9)) {
			continue;
		}
		if (!memcmp(buffer, "Comment: ", 9)) {
			if (ptr = strstr(buffer, "RSA")) {
				strcpy(pubkey, "ssh-rsa ");
				*method = pubkey;
				*method_len = 7;
				pubkeyptr = pubkey + 7;
			}
		if (ptr = strstr(buffer, "DSA")) {
				strcpy(pubkey, "ssh-dsa ");
				*method = pubkey;
				*method_len = 7;
				pubkeyptr = pubkey + 7;
			}
			continue;
		}
		if (!strcmp(buffer, "---- END SSH2 PUBLIC KEY ----"))
			break;
		strcat(pubkey, buffer);
	} while(1);
	fclose(fd);

	if (!pubkeyptr) {
		_libssh2_error(session, LIBSSH2_ERROR_FILE,
                      "Invalid key data, unknown key type");
        LIBSSH2_FREE(session, pubkey);
        return -1;
	}

    if (libssh2_base64_decode(session, (char **) &tmp, &tmp_len,
                              (char *) pubkeyptr, strlen(pubkeyptr))) {
        _libssh2_error(session, LIBSSH2_ERROR_FILE,
                      "Invalid key data, not base64 encoded");
        LIBSSH2_FREE(session, pubkey);
        return -1;
    }
    *pubkeydata = tmp;
    *pubkeydata_len = tmp_len;

    return 0;
}

/*
 * file_read_privatekey_ZMOD
 *
 * Read a private key from a ZMOD_SSH_Key file
 * generated by ZGENSSHKEY key generator
 *
 * Returns an allocated string in *privkeydata on success.
 */
int file_read_privatekey_ZMOD(LIBSSH2_SESSION * session,
                    unsigned char **privkeydata,
                    size_t *privkeydata_len,
                    const char *privkeyfile)
{
    FILE *fd;
    char c;
	char buffer[16384];
    unsigned char *privkey = NULL, *tmp, *privkeyptr = NULL;
    size_t privkey_len = 0;
    unsigned int tmp_len;
	int		rc;
	char*	ptr;

    _libssh2_debug(session, LIBSSH2_TRACE_AUTH, "Loading private key file: %s",
                   privkeyfile);
    /* Read Private Key */
    fd = fopen(privkeyfile, "r");
    if (!fd) {
        _libssh2_error(session, LIBSSH2_ERROR_FILE,
                      "Unable to open private key file");
        return -1;
    }
	privkey = LIBSSH2_ALLOC(session, 8192);
	do {
		if ((ptr = fgets(buffer, sizeof(buffer), fd)) == NULL) {
			if (fd)
				break;
			_libssh2_error(session, LIBSSH2_ERROR_FILE,
                      "Unable to read private key file");
			LIBSSH2_FREE(session, privkey);
			return -1;
		}
		do {
			if (buffer[strlen(buffer)-1] == '\r' || 
				buffer[strlen(buffer)-1] == '\n' ||
				buffer[strlen(buffer)-1] == 0x25) {
				buffer[strlen(buffer)-1] = '\0';
				continue;
			}
			break;
		} while(1);
		if (!strcmp(buffer, "---- BEGIN SSHTOOLS ENCRYPTED PRIVATE KEY ----"))
			continue;
		if (!memcmp(buffer, "Subject: ", 9)) {
			continue;
		}
		if (!memcmp(buffer, "Comment: ", 9)) {
			continue;
		}
		if (!strcmp(buffer, "---- END SSHTOOLS ENCRYPTED PRIVATE KEY ----"))
			break;
		privkeyptr = privkey;
		strcat(privkey, buffer);
	} while(1);
	fclose(fd);

	if (!privkeyptr) {
		_libssh2_error(session, LIBSSH2_ERROR_FILE,
                      "Invalid key data, unknown key type");
        LIBSSH2_FREE(session, privkey);
        return -1;
	}

    if (libssh2_base64_decode(session, (char **) &tmp, &tmp_len,
                              (char *) privkeyptr, strlen(privkeyptr))) {
        _libssh2_error(session, LIBSSH2_ERROR_FILE,
                      "Invalid key data, not base64 encoded");
        LIBSSH2_FREE(session, privkey);
        return -1;
    }
    *privkeydata = tmp;
    *privkeydata_len = tmp_len;

    return 0;
}

/*
 * libssh2_clock
 *
 * Replacement for the clock() function which doesn't seem to work on
 * AS/400. This function operates as clock() should, but it returns an 
 * unsigned long instead of clock_t.
 *
 */
unsigned long libssh2_clock(void)
{
	struct timeval	tp;
	unsigned int secs, usecs;
	long	result;
	int		rc;

	if (!libssh2_tvp) {
		libssh2_tvp = &libssh2_timeval;
		rc = gettimeofday(&libssh2_timeval, NULL);
		if (rc) 
			rc = errno;
		return 0;
	}

	rc = gettimeofday(&tp, NULL);
	if (rc)
		rc = errno;

	secs = tp.tv_sec - libssh2_timeval.tv_sec;
	if (tp.tv_usec >= libssh2_timeval.tv_usec) {
		usecs = tp.tv_usec - libssh2_timeval.tv_usec;
	} else {
		usecs = (1000000 - libssh2_timeval.tv_usec) + tp.tv_usec;
		secs--;
	}

	result = (secs * LIBSSH2_CLOCKS_PER_SEC) + usecs;

	return result;
}

#endif /* __OS400__ */