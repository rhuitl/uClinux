/* Simple ASN.1 parser
 * Copyright (C) 2000-2002 Andreas Steffen, Zuercher Hochschule Winterthur
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 *
 * RCSID $Id: asn1.c,v 0.1 2002/04/12 00:00:00 as Exp $
 */

#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <freeswan.h>

#include "constants.h"
#include "defs.h"
#include "asn1.h"
#include "log.h"
#include "pem.h"

/* Some well known object identifiers (OIDs) */

const oid_t oid_names[] = {
  {0x55,		       27, 1, "X.500" },
  {  0x04,		       14, 1, "X.509" },
  {    0x03,			1, 0, "CN"    }, /* commonName             */
  {    0x04,			1, 0, "S"     }, /* surname                */
  {    0x05,			1, 0, "SN"    }, /* serialNumber           */
  {    0x06,			1, 0, "C"     }, /* countryMame            */
  {    0x07,			1, 0, "L"     }, /* localityName           */
  {    0x08,			1, 0, "ST"    }, /* stateOrProvinceName    */
  {    0x0A,			1, 0, "O"     }, /* organizationName       */
  {    0x0B,			1, 0, "OU"    }, /* organizationalUnitName */
  {    0x0C,			1, 0, "T"     }, /* personalTitle          */
  {    0x0D,			1, 0, "D"     }, /* description            */
  {    0x29,			1, 0, "N"     }, /* name                   */
  {    0x2A,			1, 0, "G"     }, /* givenName              */
  {    0x2B,			0, 0, "I"     }, /* initials               */
  {  0x1d,			0, 1, "id-ce"			},
  {    0x0E,			1, 0, "subjectKeyIdentifier"	},
  {    0x0F,			1, 0, "keyUsage"		},
  {    0x10,			1, 0, "privateKeyUsagePeriod"	},
  {    0x11,			1, 0, "subjectAltName"		}, /* 19 */
  {    0x12,			1, 0, "issuerAltName"		},
  {    0x13,			1, 0, "basicConstraints"	}, /* 21 */
  {    0x15,			1, 0, "crlReason"		},
  {    0x1F,			1, 0, "crlDistributionPoints"	}, /* 23 */
  {    0x20,			1, 0, "certificatePolicies"	},
  {    0x23,			1, 0, "authorityKeyIdentifier"	},
  {    0x25,			0, 0, "extendedKeyUsage"	},
  {0x2A,		       28, 1, ""			},
  {  0x86,			0, 1, ""			},
  {    0x48,			0, 1, ""			},
  {	 0x86,			0, 1, ""			},
  {	   0xF7,		0, 1, ""			},
  {	     0x0D,		0, 1, "RSADSI"			},
  {	       0x01,	       19, 1, "PKCS"			},
  {		 0x01,		8, 1, "PKCS-1"			},
  {		   0x01,	1, 0, "rsaEncryption"		}, /* 35 */
  {		   0x02,	1, 0, "md2WithRSAEncryption"	}, /* 36 */
  {		   0x04,	1, 0, "md5WithRSAEncryption"	}, /* 37 */
  {		   0x05,	1, 0, "sha-1WithRSAEncryption"	}, /* 38 */
  {		   0x0B,	1, 0, "sha256WithRSAEncryption"	}, /* 39 */
  {		   0x0C,	1, 0, "sha384WithRSAEncryption"	}, /* 40 */
  {		   0x0D,	0, 0, "sha512WithRSAEncryption"	}, /* 41 */
  {		 0x07,		7, 1, "PKCS-7"			},
  {		   0x01,	1, 0, "data"			}, /* 43 */
  {		   0x02,	1, 0, "signedData"		}, /* 44 */
  {		   0x03,	1, 0, "envelopedData"		},
  {		   0x04,	1, 0, "signedAndEnvelopedData"	},
  {		   0x05,	1, 0, "digestedData"		},
  {		   0x06,	0, 0, "encryptedData"		},
  {		 0x09,		0, 1, "PKCS-9"			},
  {		   0x01,	1, 0, "E"     }, /* emailAddress      50 */
  {		   0x02,	0, 0, "unstructuredName"	},
  {	       0x02,		0, 1, "digestAlgorithm"		},
  {		 0x02,		1, 0, "md2"			}, /* 53 */
  {		 0x05,		0, 0, "md5"			}, /* 54 */
  {0x2B,		       16, 1, ""			},
  {  0x06,		       11, 1, "dod"			},
  {    0x01,			0, 1, "internet"		},
  {	 0x04,			0, 1, "private"			},
  {	   0x01,		0, 1, "enterprise"		},
  {	     0x89,		0, 1, ""			},
  {	       0x31,		0, 1, ""			},
  {		 0x01,		0, 1, ""			},
  {		   0x01,	0, 1, ""			},
  {		     0x02,	0, 1, ""			},
  {		       0x02,	0, 1, ""			},
  {			 0x4B,	0, 0, "TCGID" }, /* Trust Center Global ID */
  {  0x0E,			0, 1, "oiw"			},
  {    0x03,			0, 1, "secsig"			},
  {	 0x02,			0, 1, "algorithms"		},
  {	   0x1A,		0, 0, "id-SHA-1"		}, /* 70 */
  {0x60,			0, 1, ""			},
  {  0x86,			0, 1, ""			},
  {    0x48,			0, 1, ""			},
  {	 0x01,			0, 1, "organization"		},
  {	   0x65,		7, 1, "gov"			},
  {	     0x03,		0, 1, "csor"			},
  {	       0x04,		0, 1, "nistalgorithm"		},
  {		 0x02,		0, 1, "hashalgs"		},
  {		   0x01,	1, 0, "id-SHA-256"		},
  {		   0x02,	1, 0, "id-SHA-384"		},
  {		   0x03,	0, 0, "id-SHA-512"		},
  {	   0x86,		0, 1, ""			},
  {	     0xf8,		0, 1, ""			},
  {	       0x42,		0, 1, ""			},
  {		 0x01,		0, 1, ""			},
  {		   0x01,	1, 0, "nsCertType"		},
  {		   0x03,	1, 0, "nsRevocationUrl"		},
  {		   0x0d,	0, 0, "nsComment"		}
};


/*  If the oid is listed in the oid_names table then the corresponding
 *  position in the oid_names table is returned otherwise -1 is returned
 */
int
known_oid(chunk_t object)
{
    int oid = 0;

    while (object.len)
    {
	if (oid_names[oid].digit == *object.ptr)
	{
	    if (--object.len == 0 || oid_names[oid].down == 0)
	    {
		return oid;          /* found terminal symbol */
	    }
	    else
	    {
		object.ptr++; oid++; /* advance to next hex digit */
	    }
	}
	else
	{
	    if (oid_names[oid].next)
		oid += oid_names[oid].next;
	    else
		return -1;
	}
    }
    return -1;
}

/*
 *  Decodes the length in bytes of an ASN.1 object
 */
u_int
asn1_length(chunk_t *blob)
{
    u_char n;
    size_t len;

    /* advance from tag field on to length field */
    blob->ptr++;
    blob->len--;

    /* read first octet of length field */
    n = *blob->ptr++;
    blob->len--;

    if ((n & 0x80) == 0) { /* single length octet */
	if (n > blob->len) {
	    DBG(DBG_PARSING,
		DBG_log("number of length octets is larger than ASN.1 object")
	    )
	    return ASN1_INVALID_LENGTH;
	}
	return n;
    }

    /* composite length, determine number of length octets */
    n &= 0x7f;

    if (n > blob->len)
    {
	DBG(DBG_PARSING,
	    DBG_log("number of length octets is larger than ASN.1 object")
	)
	return ASN1_INVALID_LENGTH;
    }

    if (n > sizeof(len))
    {
	DBG(DBG_PARSING,
	    DBG_log("number of length octets is larger than limit of %d octets"
		, (int) sizeof(len))
	)
	return ASN1_INVALID_LENGTH;
    }

    len = 0;
    
    while (n-- > 0)
    {
	len = 256*len + *blob->ptr++;
	blob->len--;
    }
    if (len > blob->len)
    {
	DBG(DBG_PARSING,
	    DBG_log("length is larger than remaining blob size")
	)
	return ASN1_INVALID_LENGTH;
    }

    return len;
}

/*
 *  determines if a character string is of type ASN.1 printableString
 */
bool
is_printablestring(chunk_t str)
{
    const char printablestring_charset[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 '()+,-./:=?";
    u_int i;

    for (i = 0; i < str.len; i++)
    {
	if (strchr(printablestring_charset, str.ptr[i]) == NULL)
	    return FALSE;
    }
    return TRUE;
}

/*
 *  Converts ASN.1 UTCTIME or GENERALIZEDTIME into calender time
 */
time_t
asn1totime(const chunk_t *utctime, asn1_t type)
{
    struct tm t;
    time_t tz_offset;
    u_char *eot = NULL;

    if ((eot = memchr(utctime->ptr, 'Z', utctime->len)) != NULL)
    {
	tz_offset = 0; /* Zulu time with a zero time zone offset */
    }
    else if ((eot = memchr(utctime->ptr, '+', utctime->len)) != NULL)
    {
	int tz_hour, tz_min;

	if (sscanf(eot+1, "%2d%2d", &tz_hour, &tz_min) != 2)
	{
	    return 0; /* error in positive timezone offset format */
	}

	tz_offset = 3600*tz_hour + 60*tz_min;  /* positive time zone offset */
    }
    else if ((eot = memchr(utctime->ptr, '-', utctime->len)) != NULL)
    {
	int tz_hour, tz_min;

	if (sscanf(eot+1, "%2d%2d", &tz_hour, &tz_min) != 2)
	{
	    return 0; /* error in negative timezone offset format */
	}
	tz_offset = -3600*tz_hour - 60*tz_min;  /* negative time zone offset */
    }
    else
    {
	return 0; /* error in time format */
    }

    {
	const char* format = (type == ASN1_UTCTIME)? "%2d%2d%2d%2d%2d":
						     "%4d%2d%2d%2d%2d";

	if (sscanf(utctime->ptr, format, &t.tm_year, &t.tm_mon, &t.tm_mday,
					 &t.tm_hour, &t.tm_min) != 5)
	{
	    return 0; /* error in time st [yy]yymmddhhmm time format */
	}
    }

    /* is there a seconds field? */
    if ((eot - utctime->ptr) == ((type == ASN1_UTCTIME)?12:14))
    {
	if (sscanf(eot-2, "%2d", &t.tm_sec) != 1)
	{
	    return 0; /* error in ss seconds field format */
	}
    }
    else
    {
	t.tm_sec = 0;
    }

    /* representation of year */
    if (t.tm_year >= 1900)
    {
	t.tm_year -= 1900;
    }
    else if (t.tm_year >= 100)
    {
	return 0;
    }
    else if (t.tm_year < 50)
    {
	t.tm_year += 100;
    }

    if (t.tm_mon < 1 || t.tm_mon > 12)
    {
	return 0; /* error in month format */
    }
    /* representation of month 0..11 in struct tm */
    t.tm_mon--;

    /* set daylight saving time to off */
    t.tm_isdst = 0;

    /* compensate timezone */

    return mktime(&t) - tz_offset;
}

/*
 * Initializes the internal context of the ASN.1 parser
 */
void
asn1_init(asn1_ctx_t *ctx, chunk_t blob, u_int level0,
	bool implicit, u_int cond)
{
    ctx->blobs[0] = blob;
    ctx->level0   = level0;
    ctx->implicit = implicit;
    ctx->cond     = cond;
    memset(ctx->loopAddr, '\0', sizeof(ctx->loopAddr));
}

/*
 * Parses and extracts the next ASN.1 object
 */
bool
extract_object(asn1Object_t const *objects,
	u_int *objectID, chunk_t *object, asn1_ctx_t *ctx)
{
    asn1Object_t obj = objects[*objectID];
    chunk_t *blob;
    chunk_t *blob1;
    u_char *start_ptr;

    *object = empty_chunk;

    if (obj.flags & ASN1_END)  /* end of loop or option found */
    {
	if (ctx->loopAddr[obj.level] && ctx->blobs[obj.level+1].len > 0)
	{
	    *objectID = ctx->loopAddr[obj.level]; /* another iteration */
	    obj = objects[*objectID];
	}
	else
	{
	    ctx->loopAddr[obj.level] = 0;         /* exit loop or option*/
	    return TRUE;
	}
    }

    blob = ctx->blobs + obj.level;
    blob1 = blob + 1;
    start_ptr = blob->ptr;

    /* handle ASN.1 defaults values */

    if ( (obj.flags & ASN1_DEF) && (*start_ptr != obj.type) )
    {
	/* field is missing */

	DBG(DBG_PARSING,
	    DBG_log("L%d - %s:", ctx->level0+obj.level, obj.name);
	)
	if (obj.type & ASN1_CONSTRUCTED)
	{
	    (*objectID)++ ;  /* skip context-specific tag */
	}
	return TRUE;
    }

    /* handle ASN.1 options */

    if ( (obj.flags & ASN1_OPT) &&
	 ( blob->len == 0 || *start_ptr != obj.type) )
    {
        /* advance to end of missing option field */
	do
        {
	    (*objectID)++;
	}  while (!((objects[*objectID].flags & ASN1_END) &&
		      (objects[*objectID].level == obj.level )));
	return TRUE;
    }

    blob1->len = asn1_length(blob);

    if (blob1->len == ASN1_INVALID_LENGTH)
    {
	DBG(DBG_PARSING,
	    DBG_log("L%d - %s:  length of ASN1 object too large",
		    ctx->level0+obj.level, obj.name);
	)
	return FALSE;
    }

    blob1->ptr = blob->ptr;
    blob->ptr += blob1->len;
    blob->len -= blob1->len;

    if (*start_ptr != obj.type && !(ctx->implicit && *objectID == 0))
    {
	DBG(DBG_PARSING,
	    DBG_log("L%d - %s: ASN1 tag 0x%02x expected, but is 0x%02x",
		ctx->level0+obj.level, obj.name, obj.type, *start_ptr);
	    DBG_dump("", start_ptr, (u_int)(blob->ptr - start_ptr));
	)
	return FALSE;
    }

    DBG(DBG_PARSING,
	DBG_log("L%d - %s:", ctx->level0+obj.level, obj.name);
    )

    /* In case of "SEQUENCE OF" or "SET OF" start a loop */

    if (obj.flags & ASN1_LOOP) ctx->loopAddr[obj.level] = *objectID + 1;

    if (obj.flags & ASN1_OBJ)
    {
	object->ptr = start_ptr;
	object->len = (u_int)(blob->ptr - start_ptr);
	DBG(ctx->cond,
	    DBG_dump_chunk("", *object);
	)
    }
    else if (obj.flags & ASN1_BODY)
    {
	int oid;
	*object = *blob1;

	switch (obj.type)
	{
	case ASN1_OID:
	    oid = known_oid(*object);
	    if (oid != -1)
	    {
		DBG(DBG_PARSING,
		   DBG_log("  '%s'",oid_names[oid].name);
		)
		return TRUE;
	    }
	    break;
	case ASN1_IA5STRING:
	case ASN1_T61STRING:
	case ASN1_PRINTABLESTRING:
	case ASN1_VISIBLESTRING:
	    DBG(DBG_PARSING,
		DBG_log("  '%.*s'", (int)object->len, object->ptr);
	    )
	    return TRUE;
	case ASN1_UTCTIME:
	case ASN1_GENERALIZEDTIME:
	    DBG(DBG_PARSING,
		time_t time = asn1totime(object, obj.type);
		DBG_log("  '%s'", timetoa(&time, TRUE));
	    )
	    return TRUE;

	default:
	    break;
	}
	DBG(ctx->cond,
	    DBG_dump_chunk("", *object);
	)
    }
    return TRUE;
}

/*
 *  tests if a blob contains a valid ASN.1 set or sequence
 */
static bool
is_asn1(chunk_t blob)
{
    u_int len;
    u_char tag = *blob.ptr;

    if (tag != ASN1_SEQUENCE && tag != ASN1_SET)
    {
	DBG(DBG_PARSING,
	    DBG_log("  file content is not binary ASN.1");
	)
	return FALSE;
    }
    len = asn1_length(&blob);
    if (len != blob.len)
    {
	DBG(DBG_PARSING,
	    DBG_log("  file size does not match ASN.1 coded length");
	)
	return FALSE;
    }
    return TRUE;
}

/*  load an ASN.1 coded file with autodetection
 *  of binary DER and base64 PEM formats
 */
bool
load_asn1_file(const char* filename, const char* passphrase,
	       const char* type, chunk_t *blob)
{
    err_t ugh = NULL;
    FILE *fd;

    fd = fopen(filename, "r");
    if (fd)
    {
	int bytes;
	fseek(fd, 0, SEEK_END );
	blob->len = ftell(fd);
	if (blob->len <= 0)
 	{
            log("  %s file '%s' is zero length", type, filename);
	    fclose(fd);
            return FALSE;
	}
	rewind(fd);
	blob->ptr = alloc_bytes(blob->len, type);
	bytes = fread(blob->ptr, 1, blob->len, fd);
	fclose(fd);
//	log("  loaded %s file '%s' (%d bytes)", type, filename, bytes);

	/* try DER format */

	if (is_asn1(*blob))
	{
	    DBG(DBG_PARSING,
		DBG_log("  file coded in DER format");
	    )
	    return TRUE;
	}

	/* try PEM format */
	ugh = pemtobin(blob, passphrase);

	if (ugh == NULL)
	{
	    if (is_asn1(*blob))
	    {
		DBG(DBG_PARSING,
		    DBG_log("  file coded in PEM format");
		)
		return TRUE;
	    }

	    ugh = "file coded in unknown format, discarded";
	}

	/* a conversion error has occured */
	if (!strcmp(ugh, "file coded in unknown format, discarded"))
		log("  %s", ugh);
	pfree(blob->ptr);
	*blob = empty_chunk;
    }
    else
    {
	log("  could not open %s file '%s'", type, filename);
    }
    return FALSE;
}
