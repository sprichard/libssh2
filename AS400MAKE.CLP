/******************************************************************************/
/*                                                                            */
/* Make file for LIBSSH2. This CL Program has one parameter that turns on/off */
/* debug code generation. PARM(*NONE) is no debug, PARM(*ALL) turns on debug. */
/* This makefile assumes that OpenSSL has already been built into a library,  */
/* in this case OSSL100A, and that the source code is available on IFS. In    */
/* this case, the source code is in the following IFS directories:            */
/* LIBSSH2: /home/stanp/Products/libssh2-1.6.0                                */
/* OPENSSL: /home/openssl-1.0.0a                                              */
/*                                                                            */
/******************************************************************************/
             PGM        PARM(&DEBUG)

/******************************************************************************/
/* DEBUG parameter: *NONE or *ALL.                                            */
/******************************************************************************/
             DCL        VAR(&DEBUG) TYPE(*CHAR) LEN(10)

/******************************************************************************/
/* Set CURLIB and Library List.                                               */
/******************************************************************************/
             CHGCURLIB  CURLIB(LIBSSH2160)
             ADDLIBLE   LIB(OSSL100A)
             MONMSG     MSGID(CPF2103)

/******************************************************************************/
/* Clean build library.                                                       */
/******************************************************************************/
             DLTPGM     PGM(*CURLIB/S*)
             MONMSG     MSGID(CPF2125)
             DLTSRVPGM  SRVPGM(*CURLIB/LIBSSH2)
             MONMSG     MSGID(CPF2105)
             DLTMOD     MODULE(*CURLIB/A*)
             MONMSG     MSGID(CPF2125)
             DLTMOD     MODULE(*CURLIB/C*)
             MONMSG     MSGID(CPF2125)
             DLTMOD     MODULE(*CURLIB/G*)
             MONMSG     MSGID(CPF2125)
             DLTMOD     MODULE(*CURLIB/H*)
             MONMSG     MSGID(CPF2125)
             DLTMOD     MODULE(*CURLIB/I*)
             MONMSG     MSGID(CPF2125)
             DLTMOD     MODULE(*CURLIB/K*)
             MONMSG     MSGID(CPF2125)
             DLTMOD     MODULE(*CURLIB/M*)
             MONMSG     MSGID(CPF2125)
             DLTMOD     MODULE(*CURLIB/O*)
             MONMSG     MSGID(CPF2125)
             DLTMOD     MODULE(*CURLIB/P*)
             MONMSG     MSGID(CPF2125)
             DLTMOD     MODULE(*CURLIB/S*)
             MONMSG     MSGID(CPF2125)
             DLTMOD     MODULE(*CURLIB/T*)
             MONMSG     MSGID(CPF2125)
             DLTMOD     MODULE(*CURLIB/U*)
             MONMSG     MSGID(CPF2125)
             DLTMOD     MODULE(*CURLIB/V*)
             MONMSG     MSGID(CPF2125)


/******************************************************************************/
/* Compile modules.                                                           */
/******************************************************************************/
             CRTCMOD    MODULE(*CURLIB/AGENT) +
                          SRCSTMF('/home/stanp/Products/libssh2-1.6.0+
                          /src/agent.c') OPTION(*INCDIRFIRST) +
                          OPTIMIZE(10) DBGVIEW(&DEBUG) +
                          DEFINE('_STATIC_LIB' '_MULTI_THREADED' +
                          '_LARGE_FILES' 'LIBSSH2_OPENSSL' +
                          'SERVER_SUPPORT' OPENSSL_NO_KRB5 +
                          OPENSSL_THREADS B_ENDIAN CHARSET_EBCDIC +
                          NO_SYS_PARAM_H '_ALL_SOURCE' NO_STRINGS_H +
                          NO_SYSLOG NO_WINDOWS_BRAINDEATH +
                          OPENSSL_DOING_MAKEDEPEND +
                          '_LARGE_FILE_API' OPENSSL_NO_CMS +
                          OPENSSL_NO_CAMELLIA OPENSSL_NO_HW +
                          OPENSSL_NO_WHIRLPOOL OPENSSL_NO_JPAKE +
                          OPENSSL_NO_GOST OPENSSL_NO_GMP) +
                          TGTRLS(V5R4M0) TERASPACE(*YES) +
                          STGMDL(*INHERIT) +
                          INCDIR('/home/stanp/Products/libssh2-1.6.0/+
                          include' +
                          '/home/stanp/Products/libssh2-1.6.0/src' +
                          '/home/openssl-1.0.0a/crypto' +
                          '/home/openssl-1.0.0a' +
                          '/home/openssl-1.0.0a/include' +
                          '/QIBM/include' '/home/include' +
                          '/home/include/QSYSINC/H' '/usr/include') +
                          TGTCCSID(37)

             CRTCMOD    MODULE(*CURLIB/CHANNEL) +
                          SRCSTMF('/home/stanp/Products/libssh2-1.6.0+
                          /src/channel.c') OPTION(*INCDIRFIRST) +
                          OPTIMIZE(10) DBGVIEW(&DEBUG) +
                          DEFINE('_STATIC_LIB' '_MULTI_THREADED' +
                          '_LARGE_FILES' 'LIBSSH2_OPENSSL' +
                          'SERVER_SUPPORT' OPENSSL_NO_KRB5 +
                          OPENSSL_THREADS B_ENDIAN CHARSET_EBCDIC +
                          NO_SYS_PARAM_H '_ALL_SOURCE' NO_STRINGS_H +
                          NO_SYSLOG NO_WINDOWS_BRAINDEATH +
                          OPENSSL_DOING_MAKEDEPEND +
                          '_LARGE_FILE_API' OPENSSL_NO_CMS +
                          OPENSSL_NO_CAMELLIA OPENSSL_NO_HW +
                          OPENSSL_NO_WHIRLPOOL OPENSSL_NO_JPAKE +
                          OPENSSL_NO_GOST OPENSSL_NO_GMP) +
                          TGTRLS(V5R4M0) TERASPACE(*YES) +
                          STGMDL(*INHERIT) +
                          INCDIR('/home/stanp/Products/libssh2-1.6.0/+
                          include' +
                          '/home/stanp/Products/libssh2-1.6.0/src' +
                          '/home/openssl-1.0.0a/crypto' +
                          '/home/openssl-1.0.0a' +
                          '/home/openssl-1.0.0a/include' +
                          '/QIBM/include' '/home/include' +
                          '/home/include/QSYSINC/H' '/usr/include') +
                          TGTCCSID(37)

             CRTCMOD    MODULE(*CURLIB/COMP) +
                          SRCSTMF('/home/stanp/Products/libssh2-1.6.0+
                          /src/comp.c') OPTION(*INCDIRFIRST) +
                          OPTIMIZE(10) DBGVIEW(&DEBUG) +
                          DEFINE('_STATIC_LIB' '_MULTI_THREADED' +
                          '_LARGE_FILES' 'LIBSSH2_OPENSSL' +
                          'SERVER_SUPPORT' OPENSSL_NO_KRB5 +
                          OPENSSL_THREADS B_ENDIAN CHARSET_EBCDIC +
                          NO_SYS_PARAM_H '_ALL_SOURCE' NO_STRINGS_H +
                          NO_SYSLOG NO_WINDOWS_BRAINDEATH +
                          OPENSSL_DOING_MAKEDEPEND +
                          '_LARGE_FILE_API' OPENSSL_NO_CMS +
                          OPENSSL_NO_CAMELLIA OPENSSL_NO_HW +
                          OPENSSL_NO_WHIRLPOOL OPENSSL_NO_JPAKE +
                          OPENSSL_NO_GOST OPENSSL_NO_GMP) +
                          TGTRLS(V5R4M0) TERASPACE(*YES) +
                          STGMDL(*INHERIT) +
                          INCDIR('/home/stanp/Products/libssh2-1.6.0/+
                          include' +
                          '/home/stanp/Products/libssh2-1.6.0/src' +
                          '/home/openssl-1.0.0a/crypto' +
                          '/home/openssl-1.0.0a' +
                          '/home/openssl-1.0.0a/include' +
                          '/QIBM/include' '/home/include' +
                          '/home/include/QSYSINC/H' '/usr/include') +
                          TGTCCSID(37)

             CRTCMOD    MODULE(*CURLIB/CRYPT) +
                          SRCSTMF('/home/stanp/Products/libssh2-1.6.0+
                          /src/crypt.c') OPTION(*INCDIRFIRST) +
                          OPTIMIZE(10) DBGVIEW(&DEBUG) +
                          DEFINE('_STATIC_LIB' '_MULTI_THREADED' +
                          '_LARGE_FILES' 'LIBSSH2_OPENSSL' +
                          'SERVER_SUPPORT' OPENSSL_NO_KRB5 +
                          OPENSSL_THREADS B_ENDIAN CHARSET_EBCDIC +
                          NO_SYS_PARAM_H '_ALL_SOURCE' NO_STRINGS_H +
                          NO_SYSLOG NO_WINDOWS_BRAINDEATH +
                          OPENSSL_DOING_MAKEDEPEND +
                          '_LARGE_FILE_API' OPENSSL_NO_CMS +
                          OPENSSL_NO_CAMELLIA OPENSSL_NO_HW +
                          OPENSSL_NO_WHIRLPOOL OPENSSL_NO_JPAKE +
                          OPENSSL_NO_GOST OPENSSL_NO_GMP) +
                          TGTRLS(V5R4M0) TERASPACE(*YES) +
                          STGMDL(*INHERIT) +
                          INCDIR('/home/stanp/Products/libssh2-1.6.0/+
                          include' +
                          '/home/stanp/Products/libssh2-1.6.0/src' +
                          '/home/openssl-1.0.0a/crypto' +
                          '/home/openssl-1.0.0a' +
                          '/home/openssl-1.0.0a/include' +
                          '/QIBM/include' '/home/include' +
                          '/home/include/QSYSINC/H' '/usr/include') +
                          TGTCCSID(37)

             CRTCMOD    MODULE(*CURLIB/GLOBAL) +
                          SRCSTMF('/home/stanp/Products/libssh2-1.6.0+
                          /src/global.c') OPTION(*INCDIRFIRST) +
                          OPTIMIZE(10) DBGVIEW(&DEBUG) +
                          DEFINE('_STATIC_LIB' '_MULTI_THREADED' +
                          '_LARGE_FILES' 'LIBSSH2_OPENSSL' +
                          'SERVER_SUPPORT' OPENSSL_NO_KRB5 +
                          OPENSSL_THREADS B_ENDIAN CHARSET_EBCDIC +
                          NO_SYS_PARAM_H '_ALL_SOURCE' +
                          NO_STRINGS_HNO_SYSLOG +
                          NO_WINDOWS_BRAINDEATH +
                          OPENSSL_DOING_MAKEDEPEND +
                          '_LARGE_FILE_API' OPENSSL_NO_CMS +
                          OPENSSL_NO_CAMELLIA OPENSSL_NO_HW +
                          OPENSSL_NO_WHIRLPOOL OPENSSL_NO_JPAKE +
                          OPENSSL_NO_GOST OPENSSL_NO_GMP) +
                          TGTRLS(V5R4M0) TERASPACE(*YES) +
                          STGMDL(*INHERIT) +
                          INCDIR('/home/stanp/Products/libssh2-1.6.0/+
                          include' +
                          '/home/stanp/Products/libssh2-1.6.0/src' +
                          '/home/openssl-1.0.0a/crypto' +
                          '/home/openssl-1.0.0a' +
                          '/home/openssl-1.0.0a/include' +
                          '/QIBM/include' '/home/include' +
                          '/home/include/QSYSINC/H' '/usr/include') +
                          TGTCCSID(37)

             CRTCMOD    MODULE(*CURLIB/HOSTKEY) +
                          SRCSTMF('/home/stanp/Products/libssh2-1.6.0+
                          /src/hostkey.c') OPTION(*INCDIRFIRST) +
                          OPTIMIZE(10) DBGVIEW(&DEBUG) +
                          DEFINE('_STATIC_LIB' '_MULTI_THREADED' +
                          '_LARGE_FILES' 'LIBSSH2_OPENSSL' +
                          'SERVER_SUPPORT' OPENSSL_NO_KRB5 +
                          OPENSSL_THREADS B_ENDIAN CHARSET_EBCDIC +
                          NO_SYS_PARAM_H '_ALL_SOURCE' NO_STRINGS_H +
                          NO_SYSLOG NO_WINDOWS_BRAINDEATH +
                          OPENSSL_DOING_MAKEDEPEND +
                          '_LARGE_FILE_API' OPENSSL_NO_CMS +
                          OPENSSL_NO_CAMELLIA OPENSSL_NO_HW +
                          OPENSSL_NO_WHIRLPOOL OPENSSL_NO_JPAKE +
                          OPENSSL_NO_GOST OPENSSL_NO_GMP) +
                          SYSIFCOPT(*IFSIO) TGTRLS(V5R4M0) +
                          TERASPACE(*YES) STGMDL(*INHERIT) +
                          INCDIR('/home/stanp/Products/libssh2-1.6.0/+
                          include' +
                          '/home/stanp/Products/libssh2-1.6.0/src' +
                          '/home/openssl-1.0.0a/crypto' +
                          '/home/openssl-1.0.0a' +
                          '/home/openssl-1.0.0a/include' +
                          '/QIBM/include' '/home/include' +
                          '/home/include/QSYSINC/H' '/usr/include') +
                          TGTCCSID(37)

             CRTCMOD    MODULE(*CURLIB/ISERIES) +
                          SRCSTMF('/home/stanp/Products/libssh2-1.6.0+
                          /src/iseries.c') OPTION(*INCDIRFIRST) +
                          OPTIMIZE(10) DBGVIEW(&DEBUG) +
                          DEFINE('_STATIC_LIB' '_MULTI_THREADED' +
                          '_LARGE_FILES' 'LIBSSH2_OPENSSL' +
                          'SERVER_SUPPORT' OPENSSL_NO_KRB5 +
                          OPENSSL_THREADS B_ENDIAN CHARSET_EBCDIC +
                          NO_SYS_PARAM_H '_ALL_SOURCE' NO_STRINGS_H +
                          NO_SYSLOG NO_WINDOWS_BRAINDEATH +
                          OPENSSL_DOING_MAKEDEPEND +
                          '_LARGE_FILE_API' OPENSSL_NO_CMS +
                          OPENSSL_NO_CAMELLIA OPENSSL_NO_HW +
                          OPENSSL_NO_WHIRLPOOL OPENSSL_NO_JPAKE +
                          OPENSSL_NO_GOST OPENSSL_NO_GMP) +
                          SYSIFCOPT(*IFSIO) TGTRLS(V5R4M0) +
                          TERASPACE(*YES) STGMDL(*INHERIT) +
                          INCDIR('/home/stanp/Products/libssh2-1.6.0/+
                          include' +
                          '/home/stanp/Products/libssh2-1.6.0/src' +
                          '/home/openssl-1.0.0a/crypto' +
                          '/home/openssl-1.0.0a' +
                          '/home/openssl-1.0.0a/include' +
                          '/QIBM/include' '/home/include' +
                          '/home/include/QSYSINC/H' '/usr/include') +
                          TGTCCSID(37)

             CRTCMOD    MODULE(*CURLIB/KEEPALIVE) +
                          SRCSTMF('/home/stanp/Products/libssh2-1.6.0+
                          /src/keepalive.c') OPTION(*INCDIRFIRST) +
                          OPTIMIZE(10) DBGVIEW(&DEBUG) +
                          DEFINE('_STATIC_LIB' '_MULTI_THREADED' +
                          '_LARGE_FILES' 'LIBSSH2_OPENSSL' +
                          'SERVER_SUPPORT' OPENSSL_NO_KRB5 +
                          OPENSSL_THREADS B_ENDIAN CHARSET_EBCDIC +
                          NO_SYS_PARAM_H '_ALL_SOURCE' NO_STRINGS_H +
                          NO_SYSLOG NO_WINDOWS_BRAINDEATH +
                          OPENSSL_DOING_MAKEDEPEND +
                          '_LARGE_FILE_API' OPENSSL_NO_CMS +
                          OPENSSL_NO_CAMELLIA OPENSSL_NO_HW +
                          OPENSSL_NO_WHIRLPOOL OPENSSL_NO_JPAKE +
                          OPENSSL_NO_GOST OPENSSL_NO_GMP) +
                          TGTRLS(V5R4M0) TERASPACE(*YES) +
                          STGMDL(*INHERIT) +
                          INCDIR('/home/stanp/Products/libssh2-1.6.0/+
                          include' +
                          '/home/stanp/Products/libssh2-1.6.0/src' +
                          '/home/openssl-1.0.0a/crypto' +
                          '/home/openssl-1.0.0a' +
                          '/home/openssl-1.0.0a/include' +
                          '/QIBM/include' '/home/include' +
                          '/home/include/QSYSINC/H' '/usr/include') +
                          TGTCCSID(37)

             CRTCMOD    MODULE(*CURLIB/KEX) +
                          SRCSTMF('/home/stanp/Products/libssh2-1.6.0+
                          /src/kex.c') OPTION(*INCDIRFIRST) +
                          OPTIMIZE(10) DBGVIEW(&DEBUG) +
                          DEFINE('_STATIC_LIB' '_MULTI_THREADED' +
                          '_LARGE_FILES' 'LIBSSH2_OPENSSL' +
                          'SERVER_SUPPORT' OPENSSL_NO_KRB5 +
                          OPENSSL_THREADS B_ENDIAN CHARSET_EBCDIC +
                          NO_SYS_PARAM_H '_ALL_SOURCE' NO_STRINGS_H +
                          NO_SYSLOG NO_WINDOWS_BRAINDEATH +
                          OPENSSL_DOING_MAKEDEPEND +
                          '_LARGE_FILE_API' OPENSSL_NO_CMS +
                          OPENSSL_NO_CAMELLIA OPENSSL_NO_HW +
                          OPENSSL_NO_WHIRLPOOL OPENSSL_NO_JPAKE +
                          OPENSSL_NO_GOST OPENSSL_NO_GMP) +
                          TGTRLS(V5R4M0) TERASPACE(*YES) +
                          STGMDL(*INHERIT) +
                          INCDIR('/home/stanp/Products/libssh2-1.6.0/+
                          include' +
                          '/home/stanp/Products/libssh2-1.6.0/src' +
                          '/home/openssl-1.0.0a/crypto' +
                          '/home/openssl-1.0.0a' +
                          '/home/openssl-1.0.0a/include' +
                          '/QIBM/include' '/home/include' +
                          '/home/include/QSYSINC/H' '/usr/include') +
                          TGTCCSID(37)

             CRTCMOD    MODULE(*CURLIB/KNOWNHOST) +
                          SRCSTMF('/home/stanp/Products/libssh2-1.6.0+
                          /src/knownhost.c') OPTION(*INCDIRFIRST) +
                          OPTIMIZE(10) DBGVIEW(&DEBUG) +
                          DEFINE('_STATIC_LIB' '_MULTI_THREADED' +
                          '_LARGE_FILES' 'LIBSSH2_OPENSSL' +
                          'SERVER_SUPPORT' OPENSSL_NO_KRB5 +
                          OPENSSL_THREADS B_ENDIAN CHARSET_EBCDIC +
                          NO_SYS_PARAM_H '_ALL_SOURCE' NO_STRINGS_H +
                          NO_SYSLOG NO_WINDOWS_BRAINDEATH +
                          OPENSSL_DOING_MAKEDEPEND +
                          '_LARGE_FILE_API' OPENSSL_NO_CMS +
                          OPENSSL_NO_CAMELLIA OPENSSL_NO_HW +
                          OPENSSL_NO_WHIRLPOOL OPENSSL_NO_JPAKE +
                          OPENSSL_NO_GOST OPENSSL_NO_GMP) +
                          TGTRLS(V5R4M0) TERASPACE(*YES) +
                          STGMDL(*INHERIT) +
                          INCDIR('/home/stanp/Products/libssh2-1.6.0/+
                          include' +
                          '/home/stanp/Products/libssh2-1.6.0/src' +
                          '/home/openssl-1.0.0a/crypto' +
                          '/home/openssl-1.0.0a' +
                          '/home/openssl-1.0.0a/include' +
                          '/QIBM/include' '/home/include' +
                          '/home/include/QSYSINC/H' '/usr/include') +
                          TGTCCSID(37)

             CRTCMOD    MODULE(*CURLIB/MAC) +
                          SRCSTMF('/home/stanp/Products/libssh2-1.6.0+
                          /src/mac.c') OPTION(*INCDIRFIRST) +
                          OPTIMIZE(10) DBGVIEW(&DEBUG) +
                          DEFINE('_STATIC_LIB' '_MULTI_THREADED' +
                          '_LARGE_FILES' 'LIBSSH2_OPENSSL' +
                          'SERVER_SUPPORT' OPENSSL_NO_KRB5 +
                          OPENSSL_THREADS B_ENDIAN CHARSET_EBCDIC +
                          NO_SYS_PARAM_H '_ALL_SOURCE' NO_STRINGS_H +
                          NO_SYSLOG NO_WINDOWS_BRAINDEATH +
                          OPENSSL_DOING_MAKEDEPEND +
                          '_LARGE_FILE_API' OPENSSL_NO_CMS +
                          OPENSSL_NO_CAMELLIA OPENSSL_NO_HW +
                          OPENSSL_NO_WHIRLPOOL OPENSSL_NO_JPAKE +
                          OPENSSL_NO_GOST OPENSSL_NO_GMP) +
                          TGTRLS(V5R4M0) TERASPACE(*YES) +
                          STGMDL(*INHERIT) +
                          INCDIR('/home/stanp/Products/libssh2-1.6.0/+
                          include' +
                          '/home/stanp/Products/libssh2-1.6.0/src' +
                          '/home/openssl-1.0.0a/crypto' +
                          '/home/openssl-1.0.0a' +
                          '/home/openssl-1.0.0a/include' +
                          '/QIBM/include' '/home/include' +
                          '/home/include/QSYSINC/H' '/usr/include') +
                          TGTCCSID(37)

             CRTCMOD    MODULE(*CURLIB/MISC) +
                          SRCSTMF('/home/stanp/Products/libssh2-1.6.0+
                          /src/misc.c') OPTION(*INCDIRFIRST) +
                          OPTIMIZE(10) DBGVIEW(&DEBUG) +
                          DEFINE('_STATIC_LIB' '_MULTI_THREADED' +
                          '_LARGE_FILES' 'LIBSSH2_OPENSSL' +
                          'SERVER_SUPPORT' OPENSSL_NO_KRB5 +
                          OPENSSL_THREADS B_ENDIAN CHARSET_EBCDIC +
                          NO_SYS_PARAM_H '_ALL_SOURCE' NO_STRINGS_H +
                          NO_SYSLOG NO_WINDOWS_BRAINDEATH +
                          OPENSSL_DOING_MAKEDEPEND +
                          '_LARGE_FILE_API' OPENSSL_NO_CMS +
                          OPENSSL_NO_CAMELLIA OPENSSL_NO_HW +
                          OPENSSL_NO_WHIRLPOOL OPENSSL_NO_JPAKE +
                          OPENSSL_NO_GOST OPENSSL_NO_GMP) +
                          TGTRLS(V5R4M0) TERASPACE(*YES) +
                          STGMDL(*INHERIT) +
                          INCDIR('/home/stanp/Products/libssh2-1.6.0/+
                          include' +
                          '/home/stanp/Products/libssh2-1.6.0/src' +
                          '/home/openssl-1.0.0a/crypto' +
                          '/home/openssl-1.0.0a' +
                          '/home/openssl-1.0.0a/include' +
                          '/QIBM/include' '/home/include' +
                          '/home/include/QSYSINC/H' '/usr/include') +
                          TGTCCSID(37)

             CRTCMOD    MODULE(*CURLIB/MESSAGES) +
                          SRCSTMF('/home/stanp/Products/libssh2-1.6.0+
                          /src/messages.c') OPTION(*INCDIRFIRST) +
                          OPTIMIZE(10) DBGVIEW(&DEBUG) +
                          DEFINE('_STATIC_LIB' '_MULTI_THREADED' +
                          '_LARGE_FILES' 'LIBSSH2_OPENSSL' +
                          'SERVER_SUPPORT' OPENSSL_NO_KRB5 +
                          OPENSSL_THREADS B_ENDIAN CHARSET_EBCDIC +
                          NO_SYS_PARAM_H '_ALL_SOURCE' NO_STRINGS_H +
                          NO_SYSLOG NO_WINDOWS_BRAINDEATH +
                          OPENSSL_DOING_MAKEDEPEND +
                          '_LARGE_FILE_API' OPENSSL_NO_CMS +
                          OPENSSL_NO_CAMELLIA OPENSSL_NO_HW +
                          OPENSSL_NO_WHIRLPOOL OPENSSL_NO_JPAKE +
                          OPENSSL_NO_GOST OPENSSL_NO_GMP) +
                          TGTRLS(V5R4M0) TERASPACE(*YES) +
                          STGMDL(*INHERIT) +
                          INCDIR('/home/stanp/Products/libssh2-1.6.0/+
                          include' +
                          '/home/stanp/Products/libssh2-1.6.0/src' +
                          '/home/openssl-1.0.0a/crypto' +
                          '/home/openssl-1.0.0a' +
                          '/home/openssl-1.0.0a/include' +
                          '/QIBM/include' '/home/include' +
                          '/home/include/QSYSINC/H' '/usr/include') +
                          TGTCCSID(37)

             CRTCMOD    MODULE(*CURLIB/OPENSSL) +
                          SRCSTMF('/home/stanp/Products/libssh2-1.6.0+
                          /src/openssl.c') OPTION(*INCDIRFIRST) +
                          OPTIMIZE(10) DBGVIEW(&DEBUG) +
                          DEFINE('_STATIC_LIB' '_MULTI_THREADED' +
                          '_LARGE_FILES' 'LIBSSH2_OPENSSL' +
                          'SERVER_SUPPORT' OPENSSL_NO_KRB5 +
                          OPENSSL_THREADS B_ENDIAN CHARSET_EBCDIC +
                          NO_SYS_PARAM_H '_ALL_SOURCE' NO_STRINGS_H +
                          NO_SYSLOG NO_WINDOWS_BRAINDEATH +
                          OPENSSL_DOING_MAKEDEPEND +
                          '_LARGE_FILE_API' OPENSSL_NO_CMS +
                          OPENSSL_NO_CAMELLIA OPENSSL_NO_HW +
                          OPENSSL_NO_WHIRLPOOL OPENSSL_NO_JPAKE +
                          OPENSSL_NO_GOST OPENSSL_NO_GMP) +
                          TGTRLS(V5R4M0) TERASPACE(*YES) +
                          STGMDL(*INHERIT) +
                          INCDIR('/home/stanp/Products/libssh2-1.6.0/+
                          include' +
                          '/home/stanp/Products/libssh2-1.6.0/src' +
                          '/home/openssl-1.0.0a/crypto' +
                          '/home/openssl-1.0.0a' +
                          '/home/openssl-1.0.0a/include' +
                          '/QIBM/include' '/home/include' +
                          '/home/include/QSYSINC/H' '/usr/include') +
                          TGTCCSID(37)

             CRTCMOD    MODULE(*CURLIB/PACKET) +
                          SRCSTMF('/home/stanp/Products/libssh2-1.6.0+
                          /src/packet.c') OPTION(*INCDIRFIRST) +
                          OPTIMIZE(10) DBGVIEW(&DEBUG) +
                          DEFINE('_STATIC_LIB' '_MULTI_THREADED' +
                          '_LARGE_FILES' 'LIBSSH2_OPENSSL' +
                          'SERVER_SUPPORT' OPENSSL_NO_KRB5 +
                          OPENSSL_THREADS B_ENDIAN CHARSET_EBCDIC +
                          NO_SYS_PARAM_H '_ALL_SOURCE' NO_STRINGS_H +
                          NO_SYSLOG NO_WINDOWS_BRAINDEATH +
                          OPENSSL_DOING_MAKEDEPEND +
                          '_LARGE_FILE_API' OPENSSL_NO_CMS +
                          OPENSSL_NO_CAMELLIA OPENSSL_NO_HW +
                          OPENSSL_NO_WHIRLPOOL OPENSSL_NO_JPAKE +
                          OPENSSL_NO_GOST OPENSSL_NO_GMP) +
                          TGTRLS(V5R4M0) TERASPACE(*YES) +
                          STGMDL(*INHERIT) +
                          INCDIR('/home/stanp/Products/libssh2-1.6.0/+
                          include' +
                          '/home/stanp/Products/libssh2-1.6.0/src' +
                          '/home/openssl-1.0.0a/crypto' +
                          '/home/openssl-1.0.0a' +
                          '/home/openssl-1.0.0a/include' +
                          '/QIBM/include' '/home/include' +
                          '/home/include/QSYSINC/H' '/usr/include') +
                          TGTCCSID(37)

             CRTCMOD    MODULE(*CURLIB/PEM) +
                          SRCSTMF('/home/stanp/Products/libssh2-1.6.0+
                          /src/pem.c') OPTION(*INCDIRFIRST) +
                          OPTIMIZE(10) DBGVIEW(&DEBUG) +
                          DEFINE('_STATIC_LIB' '_MULTI_THREADED' +
                          '_LARGE_FILES' 'LIBSSH2_OPENSSL' +
                          'SERVER_SUPPORT' OPENSSL_NO_KRB5 +
                          OPENSSL_THREADS B_ENDIAN CHARSET_EBCDIC +
                          NO_SYS_PARAM_H '_ALL_SOURCE' NO_STRINGS_H +
                          NO_SYSLOG NO_WINDOWS_BRAINDEATH +
                          OPENSSL_DOING_MAKEDEPEND +
                          '_LARGE_FILE_API' OPENSSL_NO_CMS +
                          OPENSSL_NO_CAMELLIA OPENSSL_NO_HW +
                          OPENSSL_NO_WHIRLPOOL OPENSSL_NO_JPAKE +
                          OPENSSL_NO_GOST OPENSSL_NO_GMP) +
                          TGTRLS(V5R4M0) TERASPACE(*YES) +
                          STGMDL(*INHERIT) +
                          INCDIR('/home/stanp/Products/libssh2-1.6.0/+
                          include' +
                          '/home/stanp/Products/libssh2-1.6.0/src' +
                          '/home/openssl-1.0.0a/crypto' +
                          '/home/openssl-1.0.0a' +
                          '/home/openssl-1.0.0a/include' +
                          '/QIBM/include' '/home/include' +
                          '/home/include/QSYSINC/H' '/usr/include') +
                          TGTCCSID(37)

             CRTCMOD    MODULE(*CURLIB/PUBLICKEY) +
                          SRCSTMF('/home/stanp/Products/libssh2-1.6.0+
                          /src/publickey.c') OPTION(*INCDIRFIRST) +
                          OPTIMIZE(10) DBGVIEW(&DEBUG) +
                          DEFINE('_STATIC_LIB' '_MULTI_THREADED' +
                          '_LARGE_FILES' 'LIBSSH2_OPENSSL' +
                          'SERVER_SUPPORT' OPENSSL_NO_KRB5 +
                          OPENSSL_THREADS B_ENDIAN CHARSET_EBCDIC +
                          NO_SYS_PARAM_H '_ALL_SOURCE' NO_STRINGS_H +
                          NO_SYSLOG NO_WINDOWS_BRAINDEATH +
                          OPENSSL_DOING_MAKEDEPEND +
                          '_LARGE_FILE_API' OPENSSL_NO_CMS +
                          OPENSSL_NO_CAMELLIA OPENSSL_NO_HW +
                          OPENSSL_NO_WHIRLPOOL OPENSSL_NO_JPAKE +
                          OPENSSL_NO_GOST OPENSSL_NO_GMP) +
                          TGTRLS(V5R4M0) TERASPACE(*YES) +
                          STGMDL(*INHERIT) +
                          INCDIR('/home/stanp/Products/libssh2-1.6.0/+
                          include' +
                          '/home/stanp/Products/libssh2-1.6.0/src' +
                          '/home/openssl-1.0.0a/crypto' +
                          '/home/openssl-1.0.0a' +
                          '/home/openssl-1.0.0a/include' +
                          '/QIBM/include' '/home/include' +
                          '/home/include/QSYSINC/H' '/usr/include') +
                          TGTCCSID(37)

             CRTCMOD    MODULE(*CURLIB/SCP) +
                          SRCSTMF('/home/stanp/Products/libssh2-1.6.0+
                          /src/scp.c') OPTION(*INCDIRFIRST) +
                          OPTIMIZE(10) DBGVIEW(&DEBUG) +
                          DEFINE('_STATIC_LIB' '_MULTI_THREADED' +
                          '_LARGE_FILES' 'LIBSSH2_OPENSSL' +
                          'SERVER_SUPPORT' OPENSSL_NO_KRB5 +
                          OPENSSL_THREADS B_ENDIAN CHARSET_EBCDIC +
                          NO_SYS_PARAM_H '_ALL_SOURCE' NO_STRINGS_H +
                          NO_SYSLOG NO_WINDOWS_BRAINDEATH +
                          OPENSSL_DOING_MAKEDEPEND +
                          '_LARGE_FILE_API' OPENSSL_NO_CMS +
                          OPENSSL_NO_CAMELLIA OPENSSL_NO_HW +
                          OPENSSL_NO_WHIRLPOOL OPENSSL_NO_JPAKE +
                          OPENSSL_NO_GOST OPENSSL_NO_GMP) +
                          TGTRLS(V5R4M0) TERASPACE(*YES) +
                          STGMDL(*INHERIT) +
                          INCDIR('/home/stanp/Products/libssh2-1.6.0/+
                          include' +
                          '/home/stanp/Products/libssh2-1.6.0/src' +
                          '/home/openssl-1.0.0a/crypto' +
                          '/home/openssl-1.0.0a' +
                          '/home/openssl-1.0.0a/include' +
                          '/QIBM/include' '/home/include' +
                          '/home/include/QSYSINC/H' '/usr/include') +
                          TGTCCSID(37)

             CRTCMOD    MODULE(*CURLIB/SESSION) +
                          SRCSTMF('/home/stanp/Products/libssh2-1.6.0+
                          /src/session.c') OPTION(*INCDIRFIRST) +
                          OPTIMIZE(10) DBGVIEW(&DEBUG) +
                          DEFINE('_STATIC_LIB' '_MULTI_THREADED' +
                          '_LARGE_FILES' 'LIBSSH2_OPENSSL' +
                          'SERVER_SUPPORT' OPENSSL_NO_KRB5 +
                          OPENSSL_THREADS B_ENDIAN CHARSET_EBCDIC +
                          NO_SYS_PARAM_H '_ALL_SOURCE' NO_STRINGS_H +
                          NO_SYSLOG NO_WINDOWS_BRAINDEATH +
                          OPENSSL_DOING_MAKEDEPEND +
                          '_LARGE_FILE_API' OPENSSL_NO_CMS +
                          OPENSSL_NO_CAMELLIA OPENSSL_NO_HW +
                          OPENSSL_NO_WHIRLPOOL OPENSSL_NO_JPAKE +
                          OPENSSL_NO_GOST OPENSSL_NO_GMP) +
                          TGTRLS(V5R4M0) TERASPACE(*YES) +
                          STGMDL(*INHERIT) +
                          INCDIR('/home/stanp/Products/libssh2-1.6.0/+
                          include' +
                          '/home/stanp/Products/libssh2-1.6.0/src' +
                          '/home/openssl-1.0.0a/crypto' +
                          '/home/openssl-1.0.0a' +
                          '/home/openssl-1.0.0a/include' +
                          '/QIBM/include' '/home/include' +
                          '/home/include/QSYSINC/H' '/usr/include') +
                          TGTCCSID(37)

             CRTCMOD    MODULE(*CURLIB/SERVER) +
                          SRCSTMF('/home/stanp/Products/libssh2-1.6.0+
                          /src/server.c') OPTION(*INCDIRFIRST) +
                          OPTIMIZE(10) DBGVIEW(&DEBUG) +
                          DEFINE('_STATIC_LIB' '_MULTI_THREADED' +
                          '_LARGE_FILES' 'LIBSSH2_OPENSSL' +
                          'SERVER_SUPPORT' OPENSSL_NO_KRB5 +
                          OPENSSL_THREADS B_ENDIAN CHARSET_EBCDIC +
                          NO_SYS_PARAM_H '_ALL_SOURCE' NO_STRINGS_H +
                          NO_SYSLOG NO_WINDOWS_BRAINDEATH +
                          OPENSSL_DOING_MAKEDEPEND +
                          '_LARGE_FILE_API' OPENSSL_NO_CMS +
                          OPENSSL_NO_CAMELLIA OPENSSL_NO_HW +
                          OPENSSL_NO_WHIRLPOOL OPENSSL_NO_JPAKE +
                          OPENSSL_NO_GOST OPENSSL_NO_GMP) +
                          TGTRLS(V5R4M0) TERASPACE(*YES) +
                          STGMDL(*INHERIT) +
                          INCDIR('/home/stanp/Products/libssh2-1.6.0/+
                          include' +
                          '/home/stanp/Products/libssh2-1.6.0/src' +
                          '/home/openssl-1.0.0a/crypto' +
                          '/home/openssl-1.0.0a' +
                          '/home/openssl-1.0.0a/include' +
                          '/QIBM/include' '/home/include' +
                          '/home/include/QSYSINC/H' '/usr/include') +
                          TGTCCSID(37)

             CRTCMOD    MODULE(*CURLIB/SERVERKEX) +
                          SRCSTMF('/home/stanp/Products/libssh2-1.6.0+
                          /src/server_kex.c') OPTION(*INCDIRFIRST) +
                          OPTIMIZE(10) DBGVIEW(&DEBUG) +
                          DEFINE('_STATIC_LIB' '_MULTI_THREADED' +
                          '_LARGE_FILES' 'LIBSSH2_OPENSSL' +
                          'SERVER_SUPPORT' OPENSSL_NO_KRB5 +
                          OPENSSL_THREADS B_ENDIAN CHARSET_EBCDIC +
                          NO_SYS_PARAM_H '_ALL_SOURCE' NO_STRINGS_H +
                          NO_SYSLOG NO_WINDOWS_BRAINDEATH +
                          OPENSSL_DOING_MAKEDEPEND +
                          '_LARGE_FILE_API' OPENSSL_NO_CMS +
                          OPENSSL_NO_CAMELLIA OPENSSL_NO_HW +
                          OPENSSL_NO_WHIRLPOOL OPENSSL_NO_JPAKE +
                          OPENSSL_NO_GOST OPENSSL_NO_GMP) +
                          TGTRLS(V5R4M0) TERASPACE(*YES) +
                          STGMDL(*INHERIT) +
                          INCDIR('/home/stanp/Products/libssh2-1.6.0/+
                          include' +
                          '/home/stanp/Products/libssh2-1.6.0/src' +
                          '/home/openssl-1.0.0a/crypto' +
                          '/home/openssl-1.0.0a' +
                          '/home/openssl-1.0.0a/include' +
                          '/QIBM/include' '/home/include' +
                          '/home/include/QSYSINC/H' '/usr/include') +
                          TGTCCSID(37)

             CRTCMOD    MODULE(*CURLIB/SFTP) +
                          SRCSTMF('/home/stanp/Products/libssh2-1.6.0+
                          /src/sftp.c') OPTION(*INCDIRFIRST) +
                          OPTIMIZE(10) DBGVIEW(&DEBUG) +
                          DEFINE('_STATIC_LIB' '_MULTI_THREADED' +
                          '_LARGE_FILES' 'LIBSSH2_OPENSSL' +
                          'SERVER_SUPPORT' OPENSSL_NO_KRB5 +
                          OPENSSL_THREADS B_ENDIAN CHARSET_EBCDIC +
                          NO_SYS_PARAM_H '_ALL_SOURCE' NO_STRINGS_H +
                          NO_SYSLOG NO_WINDOWS_BRAINDEATH +
                          OPENSSL_DOING_MAKEDEPEND +
                          '_LARGE_FILE_API' OPENSSL_NO_CMS +
                          OPENSSL_NO_CAMELLIA OPENSSL_NO_HW +
                          OPENSSL_NO_WHIRLPOOL OPENSSL_NO_JPAKE +
                          OPENSSL_NO_GOST OPENSSL_NO_GMP) +
                          TGTRLS(V5R4M0) TERASPACE(*YES) +
                          STGMDL(*INHERIT) +
                          INCDIR('/home/stanp/Products/libssh2-1.6.0/+
                          include' +
                          '/home/stanp/Products/libssh2-1.6.0/src' +
                          '/home/openssl-1.0.0a/crypto' +
                          '/home/openssl-1.0.0a' +
                          '/home/openssl-1.0.0a/include' +
                          '/QIBM/include' '/home/include' +
                          '/home/include/QSYSINC/H' '/usr/include') +
                          TGTCCSID(37)

             CRTCMOD    MODULE(*CURLIB/SFTPSRVR) +
                          SRCSTMF('/home/stanp/Products/libssh2-1.6.0+
                          /src/sftp_server.c') OPTION(*INCDIRFIRST) +
                          OPTIMIZE(10) DBGVIEW(&DEBUG) +
                          DEFINE('_STATIC_LIB' '_MULTI_THREADED' +
                          '_LARGE_FILES' 'LIBSSH2_OPENSSL' +
                          'SERVER_SUPPORT' OPENSSL_NO_KRB5 +
                          OPENSSL_THREADS B_ENDIAN CHARSET_EBCDIC +
                          NO_SYS_PARAM_H '_ALL_SOURCE' NO_STRINGS_H +
                          NO_SYSLOG NO_WINDOWS_BRAINDEATH +
                          OPENSSL_DOING_MAKEDEPEND +
                          '_LARGE_FILE_API' OPENSSL_NO_CMS +
                          OPENSSL_NO_CAMELLIA OPENSSL_NO_HW +
                          OPENSSL_NO_WHIRLPOOL OPENSSL_NO_JPAKE +
                          OPENSSL_NO_GOST OPENSSL_NO_GMP) +
                          TGTRLS(V5R4M0) TERASPACE(*YES) +
                          STGMDL(*INHERIT) +
                          INCDIR('/home/stanp/Products/libssh2-1.6.0/+
                          include' +
                          '/home/stanp/Products/libssh2-1.6.0/src' +
                          '/home/openssl-1.0.0a/crypto' +
                          '/home/openssl-1.0.0a' +
                          '/home/openssl-1.0.0a/include' +
                          '/QIBM/include' '/home/include' +
                          '/home/include/QSYSINC/H' '/usr/include') +
                          TGTCCSID(37)

             CRTCMOD    MODULE(*CURLIB/SSHDBFILE) +
                          SRCSTMF('/home/stanp/Products/libssh2-1.6.0+
                          /src/sshDBFile.c') OPTION(*INCDIRFIRST) +
                          OPTIMIZE(10) DBGVIEW(&DEBUG) +
                          DEFINE('_STATIC_LIB' '_MULTI_THREADED' +
                          '_LARGE_FILES' 'LIBSSH2_OPENSSL' +
                          'SERVER_SUPPORT' OPENSSL_NO_KRB5 +
                          OPENSSL_THREADS B_ENDIAN CHARSET_EBCDIC +
                          NO_SYS_PARAM_H '_ALL_SOURCE' NO_STRINGS_H +
                          NO_SYSLOG NO_WINDOWS_BRAINDEATH +
                          OPENSSL_DOING_MAKEDEPEND +
                          '_LARGE_FILE_API' OPENSSL_NO_CMS +
                          OPENSSL_NO_CAMELLIA OPENSSL_NO_HW +
                          OPENSSL_NO_WHIRLPOOL OPENSSL_NO_JPAKE +
                          OPENSSL_NO_GOST OPENSSL_NO_GMP) +
                          TGTRLS(V5R4M0) TERASPACE(*YES) +
                          STGMDL(*INHERIT) +
                          INCDIR('/home/stanp/Products/libssh2-1.6.0/+
                          include' +
                          '/home/stanp/Products/libssh2-1.6.0/src' +
                          '/home/openssl-1.0.0a/crypto' +
                          '/home/openssl-1.0.0a' +
                          '/home/openssl-1.0.0a/include' +
                          '/QIBM/include' '/home/include' +
                          '/home/include/QSYSINC/H' '/usr/include') +
                          TGTCCSID(37)

             CRTCMOD    MODULE(*CURLIB/TRANSPORT) +
                          SRCSTMF('/home/stanp/Products/libssh2-1.6.0+
                          /src/transport.c') OPTION(*INCDIRFIRST) +
                          OPTIMIZE(10) DBGVIEW(&DEBUG) +
                          DEFINE('_STATIC_LIB' '_MULTI_THREADED' +
                          '_LARGE_FILES' 'LIBSSH2_OPENSSL' +
                          'SERVER_SUPPORT' OPENSSL_NO_KRB5 +
                          OPENSSL_THREADS B_ENDIAN CHARSET_EBCDIC +
                          NO_SYS_PARAM_H '_ALL_SOURCE' NO_STRINGS_H +
                          NO_SYSLOG NO_WINDOWS_BRAINDEATH +
                          OPENSSL_DOING_MAKEDEPEND +
                          '_LARGE_FILE_API' OPENSSL_NO_CMS +
                          OPENSSL_NO_CAMELLIA OPENSSL_NO_HW +
                          OPENSSL_NO_WHIRLPOOL OPENSSL_NO_JPAKE +
                          OPENSSL_NO_GOST OPENSSL_NO_GMP) +
                          TGTRLS(V5R4M0) TERASPACE(*YES) +
                          STGMDL(*INHERIT) +
                          INCDIR('/home/stanp/Products/libssh2-1.6.0/+
                          include' +
                          '/home/stanp/Products/libssh2-1.6.0/src' +
                          '/home/openssl-1.0.0a/crypto' +
                          '/home/openssl-1.0.0a' +
                          '/home/openssl-1.0.0a/include' +
                          '/QIBM/include' '/home/include' +
                          '/home/include/QSYSINC/H' '/usr/include') +
                          TGTCCSID(37)

             CRTCMOD    MODULE(*CURLIB/USERAUTH) +
                          SRCSTMF('/home/stanp/Products/libssh2-1.6.0+
                          /src/userauth.c') OPTION(*INCDIRFIRST) +
                          OPTIMIZE(10) DBGVIEW(&DEBUG) +
                          DEFINE('_STATIC_LIB' '_MULTI_THREADED' +
                          '_LARGE_FILES' 'LIBSSH2_OPENSSL' +
                          'SERVER_SUPPORT' OPENSSL_NO_KRB5 +
                          OPENSSL_THREADS B_ENDIAN CHARSET_EBCDIC +
                          NO_SYS_PARAM_H '_ALL_SOURCE' NO_STRINGS_H +
                          NO_SYSLOG NO_WINDOWS_BRAINDEATH +
                          OPENSSL_DOING_MAKEDEPEND +
                          '_LARGE_FILE_API' OPENSSL_NO_CMS +
                          OPENSSL_NO_CAMELLIA OPENSSL_NO_HW +
                          OPENSSL_NO_WHIRLPOOL OPENSSL_NO_JPAKE +
                          OPENSSL_NO_GOST OPENSSL_NO_GMP) +
                          SYSIFCOPT(*IFSIO) TGTRLS(V5R4M0) +
                          TERASPACE(*YES) STGMDL(*INHERIT) +
                          INCDIR('/home/stanp/Products/libssh2-1.6.0/+
                          include' +
                          '/home/stanp/Products/libssh2-1.6.0/src' +
                          '/home/openssl-1.0.0a/crypto' +
                          '/home/openssl-1.0.0a' +
                          '/home/openssl-1.0.0a/include' +
                          '/QIBM/include' '/home/include' +
                          '/home/include/QSYSINC/H' '/usr/include') +
                          TGTCCSID(37)

             CRTCMOD    MODULE(*CURLIB/VERSION) +
                          SRCSTMF('/home/stanp/Products/libssh2-1.6.0+
                          /src/version.c') OPTION(*INCDIRFIRST) +
                          OPTIMIZE(10) DBGVIEW(&DEBUG) +
                          DEFINE('_STATIC_LIB' '_MULTI_THREADED' +
                          '_LARGE_FILES' 'LIBSSH2_OPENSSL' +
                          'SERVER_SUPPORT' OPENSSL_NO_KRB5 +
                          OPENSSL_THREADS B_ENDIAN CHARSET_EBCDIC +
                          NO_SYS_PARAM_H '_ALL_SOURCE' NO_STRINGS_H +
                          NO_SYSLOG NO_WINDOWS_BRAINDEATH +
                          OPENSSL_DOING_MAKEDEPEND +
                          '_LARGE_FILE_API' OPENSSL_NO_CMS +
                          OPENSSL_NO_CAMELLIA OPENSSL_NO_HW +
                          OPENSSL_NO_WHIRLPOOL OPENSSL_NO_JPAKE +
                          OPENSSL_NO_GOST OPENSSL_NO_GMP) +
                          TGTRLS(V5R4M0) TERASPACE(*YES) +
                          STGMDL(*INHERIT) +
                          INCDIR('/home/stanp/Products/libssh2-1.6.0/+
                          include' +
                          '/home/stanp/Products/libssh2-1.6.0/src' +
                          '/home/openssl-1.0.0a/crypto' +
                          '/home/openssl-1.0.0a' +
                          '/home/openssl-1.0.0a/include' +
                          '/QIBM/include' '/home/include' +
                          '/home/include/QSYSINC/H' '/usr/include') +
                          TGTCCSID(37)

             CRTCMOD    MODULE(*CURLIB/SSH2) +
                          SRCSTMF('/home/stanp/Products/libssh2-1.6.0+
                          /tests/ssh2.c') OPTION(*INCDIRFIRST) +
                          OPTIMIZE(10) DBGVIEW(&DEBUG) +
                          DEFINE('_STATIC_LIB' '_MULTI_THREADED' +
                          '_LARGE_FILES' 'LIBSSH2_OPENSSL' +
                          'SERVER_SUPPORT' OPENSSL_NO_KRB5 +
                          OPENSSL_THREADS B_ENDIAN CHARSET_EBCDIC +
                          NO_SYS_PARAM_H '_ALL_SOURCE' NO_STRINGS_H +
                          NO_SYSLOG NO_WINDOWS_BRAINDEATH +
                          OPENSSL_DOING_MAKEDEPEND +
                          '_LARGE_FILE_API' OPENSSL_NO_CMS +
                          OPENSSL_NO_CAMELLIA OPENSSL_NO_HW +
                          OPENSSL_NO_WHIRLPOOL OPENSSL_NO_JPAKE +
                          OPENSSL_NO_GOST OPENSSL_NO_GMP) +
                          TGTRLS(V5R4M0) TERASPACE(*YES) +
                          STGMDL(*INHERIT) +
                          INCDIR('/home/stanp/Products/libssh2-1.6.0/+
                          include' +
                          '/home/stanp/Products/libssh2-1.6.0/src' +
                          '/home/openssl-1.0.0a/crypto' +
                          '/home/openssl-1.0.0a' +
                          '/home/openssl-1.0.0a/include' +
                          '/QIBM/include' '/home/include' +
                          '/home/include/QSYSINC/H' '/usr/include') +
                          TGTCCSID(37)

             CRTCMOD    MODULE(*CURLIB/SIMPLE) +
                          SRCSTMF('/home/stanp/Products/libssh2-1.6.0+
                          /tests/simple.c') OPTION(*INCDIRFIRST) +
                          OPTIMIZE(10) DBGVIEW(&DEBUG) +
                          DEFINE('_STATIC_LIB' '_MULTI_THREADED' +
                          '_LARGE_FILES' 'LIBSSH2_OPENSSL' +
                          'SERVER_SUPPORT' OPENSSL_NO_KRB5 +
                          OPENSSL_THREADS B_ENDIAN CHARSET_EBCDIC +
                          NO_SYS_PARAM_H '_ALL_SOURCE' NO_STRINGS_H +
                          NO_SYSLOG NO_WINDOWS_BRAINDEATH +
                          OPENSSL_DOING_MAKEDEPEND +
                          '_LARGE_FILE_API' OPENSSL_NO_CMS +
                          OPENSSL_NO_CAMELLIA OPENSSL_NO_HW +
                          OPENSSL_NO_WHIRLPOOL OPENSSL_NO_JPAKE +
                          OPENSSL_NO_GOST OPENSSL_NO_GMP) +
                          TGTRLS(V5R4M0) TERASPACE(*YES) +
                          STGMDL(*INHERIT) +
                          INCDIR('/home/stanp/Products/libssh2-1.6.0/+
                          include' +
                          '/home/stanp/Products/libssh2-1.6.0/src' +
                          '/home/openssl-1.0.0a/crypto' +
                          '/home/openssl-1.0.0a' +
                          '/home/openssl-1.0.0a/include' +
                          '/QIBM/include' '/home/include' +
                          '/home/include/QSYSINC/H' '/usr/include') +
                          TGTCCSID(37)

/******************************************************************************/
/* Create Service Program.                                                    */
/******************************************************************************/
             CRTSRVPGM  SRVPGM(LIBSSH2) MODULE(*LIBL/CHANNEL +
                          *LIBL/COMP *LIBL/CRYPT *LIBL/HOSTKEY +
                          *LIBL/KEX *LIBL/MAC *LIBL/MISC +
                          *LIBL/OPENSSL *LIBL/PACKET *LIBL/PEM +
                          *LIBL/PUBLICKEY *LIBL/SCP *LIBL/SESSION +
                          *LIBL/SFTP *LIBL/TRANSPORT *LIBL/USERAUTH +
                          *LIBL/VERSION *LIBL/ISERIES *LIBL/AGENT +
                          *LIBL/GLOBAL *LIBL/KEEPALIVE +
                          *LIBL/KNOWNHOST *LIBL/SERVER +
                          *LIBL/SERVERKEX *LIBL/SFTPSRVR +
                          *LIBL/MESSAGES *LIBL/SSHDBFILE) +
                          EXPORT(*ALL) TEXT('libssh2 Service +
                          Program') BNDSRVPGM(*LIBL/OPENSSL) +
                          OPTION(*DUPPROC *DUPVAR) +
                          ALWLIBUPD(*YES) TGTRLS(V5R4M0) +
                          STGMDL(*INHERIT)

/******************************************************************************/
/* Create test modules.                                                       */
/******************************************************************************/
             CRTPGM     PGM(SSH2) MODULE(*LIBL/SSH2) TEXT('libssh2 +
                          Test Program') BNDSRVPGM(*LIBL/LIBSSH2) +
                          OPTION(*DUPPROC *DUPVAR) +
                          TGTRLS(V5R4M0)

             CRTPGM     PGM(SIMPLE) MODULE(*LIBL/SIMPLE) +
                          TEXT('libssh2 Simple Test Program') +
                          BNDSRVPGM(*LIBL/LIBSSH2) +
                          OPTION(*DUPPROC *DUPVAR) TGTRLS(V5R4M0)

/******************************************************************************/
/* Clear Library List.                                                        */
/******************************************************************************/
             RMVLIBLE   LIB(OSSL100A)

             ENDPGM
