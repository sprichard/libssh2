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

#ifndef __OS400__

/* This module is not required for non-OS400 installations.       */

#else

/*                                                                */
/******************************************************************/
/*                                                                */
/*                ZMOD EC/FTP server Project.                     */
/*                                                                */
/*  (c) Copyright Liaison Technologies, Inc. (2011)               */
/*                                                                */
/*  Source:                                                       */
/*    Routines related to AS/400 database file processing.        */
/*                                                                */
/******************************************************************/
/**
 * DBF File utilities for SSH/SFTP.
 */

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

#include <miptrnam.h>
#include <mispcobj.h>

#include <string.h>
#include <stdlib.h>
#include <decimal.h>
#include <ctype.h>
#include <netdb.h>

typedef struct FMTFIELD
  {
    int buffpos; /* output buffer position      */
    int fieldlgh; /* field length                */
    int digits; /* field digits                */
    int decimals; /* number of decimals          */
    char fieldtype; /* field type                  */
    char varlen; /* variable length marker      */
    char edit[30]; /* edit mask                   */
  };
struct FMTFIELD *FmtFldStr;
struct FMTFIELD *FmtFld;

static void *SPCliststart;
static struct USGENHDR *GHpointer;
static struct USFLDITM *ITpointer;

struct USGENHDR
  {
  int listoffset;
  int a;
  int numitems;
  int entrysize;
  };

struct USFLDITM
  {
  char fieldname[10];
  char fieldtype;
  char usage;
  int outbuffpos;
  int inpb;
  int fieldlgh;
  int digits;
  int decimals;
  char description[50];
  char edit[2];
  int elen;
  char editword[64];
  char colhdg1[20];
  char colhdg2[20];
  char colhdg3[20];
  char intfldnam[10];
  char altfldnam[30];
  int altfldnamlgh;
  int numDBCSchar;
  char allowNull;
  char varfldind;
  char datetimefmt[4];
  char datetimesep;
  char varlen;
  int fldtextCCSID;
  int flddataCCSID;
  int fldcolhCCSID;
  int fldeditCCSID;
  };

typedef struct {
     Qus_EC_t   ec_fields;
     char       Exception_Data[100];
        } error_code_t;

char	formatted_record[65535];

char       ext_attr[10];
char       list_status;
char       rcvvar[8];
char       rjobd_fmt[8];
char       fmt_name[8];
char       space_auth[10];
char       space_dmn[10];
char       space_init;
char       space_name[20];
char       file_name[20];
char       rcd_format[10];
char       ovr_proc[1];
char       space_rep[10];
char       space_text[50];
char       space_type[10];
char       usr_prf[10];
char       *usrspc_ptr, *usrspc_base;
int        rcvlen = 8;
int        size_entry;
int        space_size = 20480;
error_code_t error_code;
decimal(5,0) numEntries;
decimal(1,0) rtnCode;
FILE       *record;

int errorFlag;
char *outptr;
int ibuffpos, fldlen;
char	*IFSrecord = NULL, *lastCharMark;
char CR, LF, Delimiter;
int TrimBlanks, TrimZeros, TrimDelm, NoZeros;
int Quote, SignVal, SignPos;
int ShowExp, PosBlank;
int fieldsInFile;


/**************************************************************/
/* terminate - terminate passed string.                       */
/**************************************************************/

static int terminate(char *string, int strlgh)
{
 char *ptr;

  if (strlgh) {
    ptr = string + (strlgh - 1);
	if (*ptr == 0) return strlgh;
    if (*ptr != ' ') return strlgh;
    do {
      if ((*ptr) && (*ptr != ' ')) {
        *++ptr = '\0';
        return strlgh;
       }
      ptr--;
    } while (--strlgh);
    *string='\0';
    return 0;
  }
  else return -1;
}

/**********************************************************************/
/* Function:      getFileType                                         */
/*                                                                    */
/* Description:   Creates the user space                              */
/*                for this program.                                   */
/**********************************************************************/
int getFileType(char *libname, char *filename)
{
	char	objname[20];
	char	objvar[200];
	int		objvarlen = 200;
	char	objtype[10];
	Qus_OBJD0200_t	*obj_desc;

	memcpy(objname,filename, 10);
	memcpy(objname+10,libname, 10);
	error_code.ec_fields.Bytes_Provided = sizeof(error_code_t);

	/* Get the Object Description */

	QUSROBJD(objvar,				/* Receiver variable              */
			objvarlen,				/* Receiver variable length       */
			"OBJD0200",				/* Format                         */
			objname,				/* File name and library          */
			"*FILE     ",			/* Object type                    */
			&error_code);			/* Error code                     */

	if(error_code.ec_fields.Bytes_Available > 0)
		return -1;

	obj_desc = (Qus_OBJD0200_t*)&objvar;
	memcpy(objtype, obj_desc->Extended_Obj_Attr, 10);

	if (!memcmp(objtype, "PF", 2))
		return 0;
	if (!memcmp(objtype, "LF", 2))
		return 1;
	if (!memcmp(objtype, "SAVF", 2))
		return 2;
	if (!memcmp(objtype, "DSPF", 2))
		return 3;

return -1;

}

/**********************************************************************/
/* Function:      crtSpace                                            */
/*                                                                    */
/* Description:   Creates the user space                              */
/*                for this program.                                   */
/**********************************************************************/
void crtSpace(char *usrSpcLib,char *usrSpc)
{
  memcpy(space_name,usrSpc, 10);
  memcpy(space_name+10,usrSpcLib, 10);
  space_init = 0x00;
  memcpy(rjobd_fmt, "OBJD0100", 8);
  memcpy(space_type, "*USRSPC   ", 10);
  memcpy(ext_attr, "          ", 10);
  memcpy(space_auth, "*ALL      ", 10);
  memcpy(space_rep, "*YES      ", 10);
  memcpy(space_dmn, "*USER     ", 10);

  error_code.ec_fields.Bytes_Provided = sizeof(error_code_t);

  /* If the user space does not exist, create it */

  QUSROBJD(rcvvar,                  /* Receiver variable              */
           rcvlen,                  /* Receiver variable length       */
           rjobd_fmt,               /* Format                         */
           space_name,              /* User space name and library    */
           space_type,              /* User object type               */
           &error_code);            /* Error code                     */
do
{
  if(error_code.ec_fields.Bytes_Available > 0)
  {
	  if(memcmp(error_code.ec_fields.Exception_Id, "CPF9801", 7) == 0)
	  {

		  QUSCRTUS(space_name,
				  ext_attr,
				  space_size,
				  &space_init,
				  space_auth,
				  space_text,
				  space_rep,
				  &error_code,
				  space_dmn);


		  if(error_code.ec_fields.Bytes_Available > 0)
		  {
			  rtnCode = 9d;
			  return;
		  }

		  /* user space created */

		  break;
	  }

	  /* if you are here, some other error on object check */

	  rtnCode = 9d;
	  return;

  }
}while(0);

      /* retrieve the user space pointer to receive the field list into */

      QUSPTRUS(space_name,
                   &usrspc_ptr,
                   &error_code);

/* could not retrieve the pointer */

          if(error_code.ec_fields.Bytes_Available > 0)
          {
             rtnCode = 9d;
             return;
          }


}

void getFieldList(char * fileName, char * libraryName)
{
	  memcpy(fmt_name, "FLDL0100", 8);
	  memcpy(file_name,fileName, 10);
	  memcpy(file_name+10,libraryName, 10);
	  memcpy(rcd_format, "*FIRST    ", 10);
	  memcpy(ovr_proc, "1", 1);

	   QUSLFLD(space_name,
	           fmt_name,
	           file_name,
	           rcd_format,
	           ovr_proc,
	           &error_code);

	   /* could not get field list */

	             if(error_code.ec_fields.Bytes_Available > 0)
	             {
	                rtnCode = 9d;
	                return;
	             }
	             numEntries = (decimal(5,0) )((Qus_Generic_Header_0100_t *) usrspc_ptr)->Number_List_Entries;

	             return;
}

/**********************************************************************/
/* Function: GetDBFields                                              */
/*                                                                    */
/* Description:   Get Database File fields into a user space.         */
/**********************************************************************/

void GetDBFields( char *libraryName, char *fileName, char *usrSpcLib,
				 char *usrSpc, decimal(5,0) *numFields, decimal(1,0) *errorCode )
{

	*numFields = 0d;
	*errorCode = 0d;

	crtSpace(usrSpcLib, usrSpc);

	if (rtnCode != 0d) {
		*errorCode = rtnCode;
		return;
	}

	getFieldList(fileName, libraryName);

    *numFields = numEntries;
    *errorCode = rtnCode;
	return;
}

/**************************************************************/
/* Exception trying to resolve to user space.                 */
/**************************************************************/

void spaceProblem (int sig)
{
 errorFlag++;
 return;
}
/**************************************************************/
/* getspcptr - get pointer to user space.                     */
/**************************************************************/

void *getspcptr(char *object, char *library)
{
 void lostconnect (int);
 int terminate (char *, int);
 char spacename[11];
 char libraryname[11];
 _SYSPTR objectSYSptr;
 _SPCPTR objectSPCptr;

  strncpy(spacename,object,10);
  spacename[10] = '\0';
  terminate(spacename,10);
  if (library) {
    strncpy(libraryname,library,10);
    libraryname[10] = '\0';
    terminate(libraryname,10);
  } else strcpy(libraryname,"*LIBL");

  signal(SIGSEGV, &spaceProblem);
  errorFlag=0;
  objectSYSptr = rslvsp(_Usrspc,spacename,libraryname,0);
  if (errorFlag)
    return NULL;
  signal(SIGSEGV, &spaceProblem);
  errorFlag=0;
  objectSPCptr = setsppfp(objectSYSptr);
  if (errorFlag)
    return NULL;
  return ((void *) objectSPCptr);
}

/**************************************************************/
/* set edit string for packed numeric.                        */
/**************************************************************/

void seteditPack( char *string )
{
  char flags[10];
  int outlgh;

  if ( TrimZeros )
    {
      /* Do we need to always include the sign? */
      if ( ( SignVal ) && ( SignPos == 0 ) )
        strcpy(flags,"+");
      else
        strcpy(flags,"");
      /* Leave minimum number of zeros?         */
      sprintf( string, "%%%sD(30,%d)", flags, FmtFld->decimals );
    }
  else
    {
      outlgh = FmtFld->digits;
      if ( ( SignVal ) && ( SignPos == 0 ) )
        strcpy(flags,"+");
      else
        {
          if ( ( Delimiter ) || ( SignPos ) )
            strcpy(flags,"");
          else
            if ( PosBlank )
              {
                strcpy(flags,"0");
                if ( FmtFld->digits == FmtFld->decimals )
                  outlgh++;
              }
            else
              strcpy(flags," ");
        }
      if ( *flags )
        outlgh++;
      if ( FmtFld->decimals )
        outlgh++;
      sprintf( string, "%%%s0%dD(30,%d)", flags, outlgh, FmtFld->decimals );
    }

  return;
}
/**************************************************************/
/* set edit string for floating point.                        */
/**************************************************************/

void seteditFloat( char *string )
{
  char flags[10];
  int outlgh;

  if ( TrimZeros )
    {
      /* Do we need to always include the sign? */
      if ( SignVal )
        strcpy(flags,"+");
      else
        strcpy(flags,"");
      /* Use exponent form or regular number */
      if ( ShowExp )
        sprintf( string, "%%%sE", flags );
      else
        sprintf( string, "%%%sf", flags );
    }
  else
    {
      outlgh = FmtFld->digits;
      if ( ( SignVal ) && ( SignPos == 0 ) )
        strcpy(flags,"+");
      else
        {
          if ( ( Delimiter ) || ( SignPos ) )
            strcpy(flags,"");
          else
            if ( PosBlank )
              strcpy(flags,"0");
            else
              strcpy(flags," ");
        }
      if ( ShowExp )
        {
          sprintf( string, "%%%s0%dE", flags, FmtFld->digits );
        }
      else
        {
          if ( *flags )
            outlgh++;
          outlgh++;
          sprintf( string, "%%%s0%df", flags, FmtFld->digits );
        }
    }

  return;
}

/**************************************************************/
/* process an alpha field                                     */
/**************************************************************/

void procAlpha( char *record )
{
  int offset;
  /* Check if field is variable */
  if ( FmtFld->varlen == '1' )
    {
      fldlen = record[ibuffpos++];
      fldlen <<= 8;
      fldlen += record[ibuffpos++];
    }
  /* Should I trim?             */
  if ( TrimBlanks )
    {
      offset = ibuffpos + fldlen;
      while ( fldlen )
        {
          if ( record[--offset] != ' ' )
            break;
          fldlen--;
        }
      if ( fldlen == 0 )
        {
          /* Minimum blanks required? */
          if ( TrimBlanks == 1 )
            return;
          fldlen = 1;
        }
    }
  if ( Delimiter )
    {
      if ( ( Quote ) && ( fldlen ) )
        {
          *outptr = '"';
          outptr++;
          offset = ibuffpos + fldlen;
          do
            {
              *outptr = record[ibuffpos++];
              if ( *outptr == '"' )
                {
                  outptr++;
                  *outptr = '"';
                }
              outptr++;
            } while ( ibuffpos < offset );
          *outptr = '"';
          outptr++;
          lastCharMark = outptr;
          return;
        }
    }
  memcpy(outptr,&record[ibuffpos],fldlen);
  outptr += fldlen;
  lastCharMark = outptr;

  return;
}
/**************************************************************/
/* process a packed numeric field                             */
/**************************************************************/

void procPacked( char *record )
{
  void outPutNumber (decimal(30,0));

  decimal(30,0) wrkdec;
  int offset;

  wrkdec = 0;
  /* Max packed length is 16 actual buffer bytes. */
  offset = 16 - fldlen;
  memcpy(((char *) &wrkdec)+offset,&record[ibuffpos],fldlen);
  outPutNumber( wrkdec );
  return;
}
/**************************************************************/
/* process a zoned numeric field                              */
/**************************************************************/

void procZoned( char *record )
{
  void outPutNumber (decimal(30,0));
  decimal(30,0) wrkdec;
  int offset, length;
  wrkdec = 0;
  length = fldlen;
  offset = ibuffpos;
  toploop: ;
  wrkdec += ( record[offset] & '\x0f' );
  length--;
  if ( length )
    {
      offset++;
      wrkdec *= 10;
      goto toploop;
    }
  if ( ( record[offset] >> 4 ) < 15 )
    wrkdec = 0 - wrkdec;
  outPutNumber( wrkdec );
  return;
}
/**************************************************************/
/* process a binary numeric field                             */
/**************************************************************/

void procBinary( char *record )
{
  void outPutNumber (decimal(30,0));

  decimal(30,0) wrkdec;
  long int binaryNumber;
  int offset;

  binaryNumber = 0; /* TMC01 */
  offset = ( sizeof(long int) ) - fldlen;
  memcpy(((char *) &binaryNumber)+offset,&record[ibuffpos],fldlen);
  wrkdec = binaryNumber;
  outPutNumber( wrkdec );
  return;
}
/**************************************************************/
/* output a numeric value.                                    */
/**************************************************************/

void outPutNumber (decimal(30,0) Number)
  {
    int i, neg;
    /* If number is zero, should I output anything */
    if ((Number==0) && (NoZeros))
    return;
    if (SignPos)
      {
        if (Number<0)
          {
            neg=1;
            Number=0-Number;
          }
        else neg=0;
        i = sprintf(outptr,FmtFld->edit,Number);
        outptr+=i;
        if (neg)
          {
            *outptr='-';
            outptr+=1;
          }
        else if (SignVal)
          {
            *outptr='+';
            outptr+=1;
          }
        else if (Delimiter==0)
          {
            *outptr=' ';
            outptr+=1;
          }
      }
    else
      {
        i = sprintf(outptr,FmtFld->edit,Number);
        outptr+=i;
      }
    if (i)
    lastCharMark=outptr;

    return;
  }
/**************************************************************/
/* process a floating point field                             */
/**************************************************************/

void procFloat( char *record )
{
  int i;
  float wrkfloat;
  double wrkdouble;

  if ( fldlen == sizeof(float) )
    {
      wrkfloat = 0;
      memcpy((char *) &wrkfloat,&record[ibuffpos],fldlen);
      /* If number is zero, should I output anything */
      if ( ( wrkfloat == 0 ) && ( NoZeros ) )
        return;
      i = sprintf( outptr, FmtFld->edit, wrkfloat );
    }
  else
    {
      wrkdouble = 0;
      memcpy((char *) &wrkdouble,&record[ibuffpos],fldlen);
      /* If number is zero, should I output anything */
      if ( ( wrkdouble == 0 ) && ( NoZeros ) )
        return;
      i = sprintf( outptr, FmtFld->edit, wrkdouble );
    }
  outptr += i;
  if ( i )
    lastCharMark = outptr;
  return;
}

/**************************************************************/
/* process an IFS record.                                     */
/**************************************************************/

int rfmtDBFrec( char *record, int reclgh )
{
  void procAlpha( char * );
  void procPacked( char * );
  void procZoned( char * );
  void procBinary( char * );
  void procFloat( char * );

  int fieldcount;

  outptr = lastCharMark = IFSrecord;

  /* Start at first field */
  FmtFld = FmtFldStr;
  fieldcount = 0;

  do
    {
      ibuffpos = FmtFld->buffpos;
      fldlen = FmtFld->fieldlgh;
      /* What is the data type? */
      switch ( FmtFld->fieldtype )
        {
        case 'A':
          procAlpha( record );
          break;
        case 'P':
          procPacked( record );
          break;
        case 'S':
          procZoned( record );
          break;
        case 'B':
          procBinary( record );
          break;
        case 'F':
          procFloat( record );
          break;
        default:
          procAlpha( record );
          break;
        }
      if ( Delimiter )
        {
          *outptr = Delimiter;
          outptr++;
        }
      /* More fields?           */
      fieldcount++;
      if ( fieldcount < fieldsInFile )
        {
          FmtFld++;
        }
      else
        {
          /* Return the length of the IFS output. */
          if ( TrimDelm )
            return ( lastCharMark - IFSrecord );
          else
            {
              if ( Delimiter )
                return ( outptr - IFSrecord - 1 );
              else
                return ( outptr - IFSrecord );
            }
        }
    } while ( 1 );
}


/**************************************************************/
/* set up for file data formatting.                           */
/**************************************************************/

int set4formatting( char *library, char *file )
{
  void *getspcptr( char *, char * );
  void GetDBFields(char *, char *, char *, char *, decimal(5,0) *,
      decimal(1,0) *);
  void seteditPack( char * );
  void seteditFloat( char * );

  void *userspace;
  int fieldcount;
  decimal(5,0) numfields;
  decimal (1,0) errorCode;

  /* Set up the field user space for the file.                  */
  numfields = errorCode = 0;
  GetDBFields( library, file, "QTEMP     ", "ZMDBFFDSPC", &numfields, &errorCode );
  if ( errorCode != 0 )
    return -1;

  /* Get pointers to the user space.                            */
  if ( ( userspace = getspcptr( "ZMDBFFDSPC", "QTEMP     " ) ) == NULL )
    return -1;
  /* Set to space generic header.                               */
  GHpointer = (struct USGENHDR *) ( (char *) userspace + 124 );
  /* Set to first entry in the list                             */
  SPCliststart = (void *) ( (char *) userspace + ( GHpointer->listoffset ) );
  /* Get space to hold the reformatting list */
  fieldsInFile = GHpointer->numitems;
  if ( ( FmtFldStr = (struct FMTFIELD *) malloc( fieldsInFile
      * ( sizeof(struct FMTFIELD) ) ) ) == NULL )
    return -1;
  /* Start at first field */
  ITpointer = (struct USFLDITM *) SPCliststart;
  FmtFld = FmtFldStr;

  fieldcount = 0;

  do
    {
      FmtFld->buffpos = ITpointer->outbuffpos - 1;
      FmtFld->fieldlgh = ITpointer->fieldlgh;
      FmtFld->digits = ITpointer->digits;
      FmtFld->decimals = ITpointer->decimals;
      FmtFld->fieldtype = ITpointer->fieldtype;
      FmtFld->varlen = ITpointer->varlen;
      /* What is the data type? */
      switch ( ITpointer->fieldtype )
        {
        case 'A':
          break;
        case 'P':
          seteditPack( FmtFld->edit );
          break;
        case 'S':
          seteditPack( FmtFld->edit );
          break;
        case 'B':
          seteditPack( FmtFld->edit );
          break;
        case 'F':
          seteditFloat( FmtFld->edit );
          break;
        default:
          break;
        }
      /* More fields?           */
      fieldcount++;
      if ( fieldcount < fieldsInFile )
        {
          ITpointer = (struct USFLDITM *) ( (char *) ITpointer
              + GHpointer->entrysize );
          FmtFld++;
        }
      else
        break;
    } while ( 1 );

  return 0;

}

int sshDBFOpenRead(LIBSSH2_SFTP_HANDLE *handle, char *ifsFileName)
{

	LIBSSH2_SFTP *sftp = handle->sftp;
	_RFILE		*sshRFILE;
	_XXOPFB_T	*sshOPFB;
	char		*ptr, *cp;
	char		fullFileName[40];
	char		libName[11];
	char		fileName[11];
	char		openParms[256];
	int			i, rc, filetype;

	memset(libName, 0, sizeof(libName));
	memset(fileName, 0, sizeof(fileName));
	memset(fullFileName, 0, sizeof(fullFileName));

	ptr = ifsFileName + 10;				// Skip "/QSYS.LIB/"
	cp = strchr(ptr, '.');				// Find ".LIB"
	memcpy(libName, ptr, cp - ptr);		// Copy Library Name.
	ptr = cp + 5;						// Skip ".LIB/"
	cp = strchr(ptr, '.');				// Find ".FILE"
	memcpy(fileName, ptr, cp - ptr);	// Copy File Name.

	strcpy(fullFileName, libName);
	strcat(fullFileName, "/");
	strcat(fullFileName, fileName);
	strcat(fullFileName, "(*FIRST)");

	for (i=0; i<10; i++)
		if (libName[i] == 0) libName[i] = ' ';
	for (i=0; i<10; i++)
		if (fileName[i] == 0) fileName[i] = ' ';

	if (handle->format_records) {
		if ( ( rc = set4formatting( libName, fileName ) ) < 0 )
			return -1;
	}

	filetype = getFileType(libName, fileName);
	if (filetype < 0) return -1;

	strcpy(openParms, "rr, riofb=N");
	// If filetype is PF or LF, add blkrcd and nullcap.
	if (filetype < 2)
		strcat(openParms, " blkrcd=Y nullcap=Y");

	sshRFILE = _Ropen(fullFileName, openParms);

	if (!sshRFILE) {
		sftp->last_errno = errno;
		return -1;
	}

	sshOPFB = _Ropnfbk(sshRFILE);

	if (!sshOPFB) return -1;

	handle->fileptr = (void*)sshRFILE;
	handle->feedback = (void*)sshOPFB;
	handle->record_len = sshOPFB->pgm_record_len;

	return 0;

}

int sshDBFOpenWrite(LIBSSH2_SFTP_HANDLE *handle, char *ifsFileName)
{

	LIBSSH2_SFTP *sftp = handle->sftp;
	_RFILE		*sshRFILE;
	_XXOPFB_T	*sshOPFB;
	char		*ptr, *cp;
	char		fullFileName[40];
	char		libName[11];
	char		fileName[11];
	char		syscmd[128];
	char		openMode[128];
	int			i, rc, filetype;

	memset(libName, 0, sizeof(libName));
	memset(fileName, 0, sizeof(fileName));
	memset(syscmd, 0, sizeof(syscmd));
	memset(fullFileName, 0, sizeof(fullFileName));

	ptr = ifsFileName + 10;				// Skip "/QSYS.LIB/"
	cp = strchr(ptr, '.');				// Find ".LIB"
	memcpy(libName, ptr, cp - ptr);		// Copy Library Name.
	ptr = cp + 5;						// Skip ".LIB/"
	cp = strchr(ptr, '.');				// Find ".FILE"
	memcpy(fileName, ptr, cp - ptr);	// Copy File Name.

	strcpy(fullFileName, libName);
	strcat(fullFileName, "/");
	strcat(fullFileName, fileName);
	strcat(fullFileName, "(*FIRST)");

	for (i=0; i<10; i++)
		if (libName[i] == 0) libName[i] = ' ';
	for (i=0; i<10; i++)
		if (fileName[i] == 0) fileName[i] = ' ';

	strcpy(openMode, "wr, riofb=N");
	if (handle->append) strcpy(openMode, "ar, riofb=N");

	filetype = getFileType(libName, fileName);
	if (filetype < 0) return -1;

	// If SAVF, clear it first.
	if (filetype == 2) {
		strcpy(syscmd, "CLRSAVF FILE(");
		strcat(syscmd, libName);
		terminate(syscmd, strlen(syscmd));
		strcat(syscmd, "/");
		strcat(syscmd, fileName);
		terminate(syscmd, strlen(syscmd));
		strcat(syscmd, ")");
		system(syscmd);
	}

	// If filetype is PF or LF, add blkrcd and nullcap.
	if (filetype < 2)
		strcat(openMode, " blkrcd=Y");

	sshRFILE = _Ropen(fullFileName, openMode);

	if (!sshRFILE) {
		sftp->last_errno = errno;
		return -1;
	}

	sshOPFB = _Ropnfbk(sshRFILE);

	if (!sshOPFB) return -1;

	handle->fileptr = (void*)sshRFILE;
	handle->feedback = (void*)sshOPFB;
	handle->record_len = sshOPFB->pgm_record_len;
	handle->write_mode = 1;
	if (handle->stream) handle->truncate = 0;

	return 0;

}

int sshDBFClose(LIBSSH2_SFTP_HANDLE *handle)
{
	LIBSSH2_SFTP *sftp = handle->sftp;

	int		rc = 0;

	if (handle->write_mode && handle->bytes_to_send)
		rc = write_record(handle);

	rc = _Rclose(handle->fileptr);
	handle->fileptr = NULL;
	handle->feedback = NULL;
	if (rc) {
		sftp->last_errno = errno;
		rc = errno;
	}
	return rc;
}

int sshDBFRead(LIBSSH2_SFTP_HANDLE *handle, char* buffer, int buffer_len)
{
	LIBSSH2_SFTP *sftp = handle->sftp;
	int			rc = 0;
	int			bytes_read = 0;
	int			bytes_left = 0;
	int			rfb_bytes = 0;
	char		*bufptr, *in_ptr;
	_RIOFB_T	*rfb;

	if (!buffer) return -1;
	if (!buffer_len) return 0;

	bufptr = buffer;
	bytes_left = buffer_len;

	TrimBlanks = TrimZeros = TrimDelm = SignVal = SignPos = Quote = ShowExp = 0;
	NoZeros = PosBlank = 0;

	CR = handle->CRLF[0];
	LF = handle->CRLF[1];
	Delimiter = handle->format_delimiter;
	if (handle->format_trimb == 'Y') TrimBlanks = 1;
	if (handle->format_trimb == 'M') TrimBlanks = 2;
	if (handle->format_trimz == 'Y') {
		TrimZeros = 1;
		NoZeros = 1;
	}
	if (handle->format_trimz == 'M') TrimZeros = 2;
	if ((handle->format_delimiter) && (handle->format_trimd == 'Y'))
		TrimDelm = 1;
	if (handle->format_signval == 'A') SignVal = 1;
	if (handle->format_signval == 'Z') SignVal = 2;
	if (handle->format_signpos == 'T') SignPos = 1;
	if (handle->format_quote == 'Y') Quote = 1;
	if (handle->format_exponent == 'Y') ShowExp = 1;
	if (SignVal > 1) {
		PosBlank = 1;
		SignVal = 0;
	}

	if (!handle->file_buffer) {
		if ((handle->file_buffer = malloc(handle->record_len + 5)) == NULL)
			return -1;
	}

	do {
		if (!handle->bytes_remaining) {
			errno = 0;
			rfb = _Rreadn( handle->fileptr, handle->file_buffer, handle->record_len,
				__NO_LOCK );
			rfb_bytes = rfb->num_bytes;
			if (rfb_bytes != handle->record_len) {
				sftp->last_errno = errno;
				break;
			}
			handle->bytes_in_file += rfb_bytes;
		} else {
			rfb_bytes = handle->bytes_remaining;
		}

		if (!handle->translate) {
			// We are in binary mode. Just add the data to the buffer.
			in_ptr = handle->file_buffer;
		} else {
			if (handle->bytes_remaining) {
				handle->bytes_remaining = 0;
				in_ptr = handle->file_buffer;
			} else {
				// We are in text mode. Format the data if requested,
				// translate the data, add record seperators and add to
				// the buffer.
				if (handle->format_records) {
					// Format the record.
					IFSrecord = formatted_record;
					rc = rfmtDBFrec( handle->file_buffer, rfb_bytes );
					if (rc < 0) return -1;
					rfb_bytes = rc;
					libssh2_make_ascii(formatted_record, rfb_bytes);
				} else {
					if (handle->remove_blanks) {
						rfb_bytes = terminate(handle->file_buffer, rfb_bytes);
					}
					memcpy(formatted_record, handle->file_buffer, rfb_bytes);
					libssh2_make_ascii(formatted_record, rfb_bytes);
				}
				memcpy(formatted_record + rfb_bytes, (void*)&handle->CRLF, strlen(handle->CRLF));
				rfb_bytes += strlen(handle->CRLF);
				in_ptr = formatted_record;
			}
		}
		if (bytes_left >= rfb_bytes) {
			memcpy(bufptr, in_ptr, rfb_bytes);
			bufptr += rfb_bytes;
			bytes_left -= rfb_bytes;
			bytes_read += rfb_bytes;
			handle->bytes_remaining = 0;
		} else {
			memcpy(bufptr, in_ptr, bytes_left);
			memcpy(handle->file_buffer, in_ptr + bytes_left, rfb_bytes - bytes_left);
			handle->bytes_remaining = rfb_bytes - bytes_left;
			bytes_read += bytes_left;
			break;
		}
		if (!bytes_left) break;
	} while(1);

	return bytes_read;
}

int sshDBFWrite(LIBSSH2_SFTP_HANDLE *handle, char* buffer, int buffer_len)
{
	LIBSSH2_SFTP *sftp = handle->sftp;
	int			rc = 0;
	int			bytes_written = 0;
	int			bytes_left = 0;
	int			record_len;
	int			skipping = 0;
	char		c;
	char		*bufptr, *in_ptr;
	char		record[33000];

	if (!buffer) return -1;
	if (!buffer_len) {
		if (!handle->bytes_to_send) return 0;
		return write_record(handle);
	}

	bufptr = buffer;
	bytes_left = buffer_len;

	if (!handle->file_buffer) {
		if ((handle->file_buffer = malloc(handle->record_len + 5)) == NULL)
			return -1;
	}

	while(bytes_left > 0) {
		c = bufptr[0];
		bufptr++;
		bytes_left--;
		bytes_written++;
		if (!handle->translate) {
			rc = add_to_record(handle, c);
			if (rc < 0) return rc;
		} else {
			if (handle->haveCR) {
				handle->haveCR = 0;
				if (c != '\n' && c != 0x25) {
					rc = add_to_record(handle, '\r');
					if (rc < 0) return rc;
					if (rc > 0 && handle->truncate) skipping = 1;
				} else {
					rc = 0;
					if (!handle->stream && !skipping)
						rc = write_record(handle);
					skipping = 0;
					if (rc < 0) return rc;
					continue;
				}
			}
			if (c == '\r') {
				handle->haveCR = 1;
				continue;
			}
#if 0
			if (c == '\n' || c == 0x25) {
				rc = 0;
				if (!skipping)
					rc = write_record(handle);
				skipping = 0;
				if (rc < 0) return rc;
				continue;
			}
#endif

			if (skipping) continue;
			rc = add_to_record(handle, c);
			if (rc < 0) return rc;
			if (rc > 0 && handle->truncate) skipping = 1;
		}
	}

	return bytes_written;

}

static int add_to_record(LIBSSH2_SFTP_HANDLE *handle, char c)
{
	int		rc;

	handle->file_buffer[handle->bytes_to_send++] = c;

	if (handle->bytes_to_send < handle->record_len) return 0;

	rc = write_record(handle);
	if (rc < 0) 
		return rc;
	return 1;

}

static int write_record(LIBSSH2_SFTP_HANDLE *handle)
{
	LIBSSH2_SFTP *sftp = handle->sftp;
	int			rc, err_code;
	_RIOFB_T	*rfb;

	if (handle->bytes_to_send < handle->record_len) {
		if (handle->translate) {
			memset(handle->file_buffer + handle->bytes_to_send, ' ',
				handle->record_len - handle->bytes_to_send);
		} else {
			memset(handle->file_buffer + handle->bytes_to_send, 0,
				handle->record_len - handle->bytes_to_send);
		}
		handle->bytes_to_send = handle->record_len;
	}

	rfb = _Rwrite( handle->fileptr, handle->file_buffer, handle->bytes_to_send);
	rc = handle->bytes_to_send;
	handle->bytes_to_send = 0;
	if (rfb->num_bytes != rc) {
		rc = -1;
		sftp->last_errno = errno;
		err_code = errno;
	}
	handle->bytes_in_file += rfb->num_bytes;

	return rc;
}
#endif
