/*
 * $Id: arjcrypt.h,v 1.1.1.1 2002/03/28 00:01:13 andrew_belov Exp $
 * ---------------------------------------------------------------------------
 * All defines regarding ARJCRYPT operations are stored in this file
 *
 */

#ifndef ARJCRYPT_INCLUDED
#define ARJCRYPT_INCLUDED

/* Signature for identifying ARJCRYPT modules */

#define ARJCRYPT_SIG "Signature to search"

/* ARJCRYPT operation modes */

#define ARJCRYPT_V2_INIT           0
#define ARJCRYPT_INIT              1
#define ARJCRYPT_ENCODE            2
#define ARJCRYPT_DECODE            3
#define ARJCRYPT_CIPHER            4
#define ARJCRYPT_DECIPHER          5

/* ARJCRYPT return codes */

#define ARJCRYPT_RC_OK             0
#define ARJCRYPT_RC_INITIALIZED    2
#define ARJCRYPT_RC_INIT_V2        3
#define ARJCRYPT_RC_ERROR         -1

/* Inquiry types */

#define ARJCRYPT_INQ_INIT          1    /* Initialization request */
#define ARJCRYPT_INQ_RSP           2    /* Initialization response */

#pragma pack(1)

/* Structure of exchange block */

struct arjcrypt_exblock
{
 int mode;
 int len;
 char FAR *data;
 char FAR *password;
 unsigned long l_modifier[2];
 int rc;
 int (FAR *ret_addr)();
 int inq_type;                          /* ARJCRYPT v 2.0+ */
 int flags;                             /* ARJCRYPT v 2.0+ */
};

#pragma pack()

#endif
