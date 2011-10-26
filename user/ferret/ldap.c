/* Copyright (c) 2007 by Errata Security */
#include "protos.h"
#include "netframe.h"
#include "ferret.h"
#include "formats.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

const unsigned 
asn1_length(struct NetFrame *frame, const unsigned char *px, unsigned length, unsigned *r_offset)
{
	unsigned result;

	if ( (*r_offset >= length) 
		|| (px[*r_offset] & 0x80) 
		&& ((*r_offset) + (px[*r_offset]&0x7F) >= length)) {
		FRAMERR(frame, "snmp: truncated\n");
		*r_offset = length;
		return 0xFFFFffff;
	}
	result = px[(*r_offset)++];
	if (result & 0x80) {
		unsigned length_of_length = result & 0x7F;
		if (length_of_length == 0) {
			FRAMERR(frame, "snmp: unexpected value\n");
			*r_offset = length;
			return 0xFFFFffff;
		}
		result = 0;
		while (length_of_length) {
			result = result * 256 + px[(*r_offset)++];
			if (result > 0x10000) {
				FRAMERR(frame, "snmp: unexpected value\n");
				*r_offset = length;
				return 0xFFFFffff;
			}
			length_of_length--;
		}
	}
	return result;
}


const unsigned 
asn1_integer(struct NetFrame *frame, const unsigned char *px, unsigned length, unsigned *r_offset)
{
	unsigned int_length;
	unsigned result;
	unsigned tag;

	tag = px[(*r_offset)++];
	if (tag != 0x0a && tag != 0x02 && tag != 0x01)
		FRAMERR_BADVAL(frame, "asn1", tag);

	int_length = asn1_length(frame, px, length, r_offset);
	if (int_length == 0xFFFFffff) {
		*r_offset = length;
		return 0xFFFFffff;
	}
	if (*r_offset + int_length > length) {
		FRAMERR(frame, "snmp: truncated\n");
		*r_offset = length;
		return 0xFFFFffff;
	}

	result = 0;
	while (int_length--)
		result = result * 256 + px[(*r_offset)++];

	return result;
}

#define asn1_enumerated asn1_integer
#define asn1_boolean asn1_integer

static unsigned 
asn1_tag(const unsigned char *px, unsigned length, unsigned *r_offset)
{
	if (*r_offset >= length)
		return 0;
	return px[(*r_offset)++];
}

static void
asn1_string(struct NetFrame *frame, const unsigned char *px, unsigned length, unsigned *r_offset, const unsigned char **r_str, unsigned *r_str_length)
{
	unsigned len;
	unsigned tag;

	if (*r_offset >= length)
		return;
	
	tag = asn1_tag(px, length, r_offset);

	len = asn1_length(frame, px, length, r_offset);

	*r_str = px + *r_offset;
	*r_str_length = len;

	*r_offset += len;
}

struct AttributeValueAssertion {
	const unsigned char *attributeDescription;
	unsigned attributeDescription_length;

	const unsigned char *assertionValue;
	unsigned assertionValue_length;
};
struct FILTER
{
	unsigned tag;
	unsigned count;
	union {
		struct FILTER *filters[128];
		struct AttributeValueAssertion *attributes[64];
		struct AttributeType {
			const unsigned char *attributeType;
			unsigned attributeType_length;
		} at;

		struct {
			const unsigned char *attributeType;
			unsigned attributeType_length;
		} substringfilter;

		struct AttributeValueAssertion val;
	} data;
};

struct LDAP
{
	unsigned message_id;
	unsigned message_type;
	const unsigned char *basedn;
	unsigned basedn_length;
	unsigned scope;
	unsigned dereference;
	unsigned size_limit;
	unsigned time_limit;
	unsigned attribute_only;

	struct FILTER *filter;
};


static void process_ldap_filter(struct NetFrame *frame, const unsigned char *px, unsigned length, unsigned *r_offset, struct FILTER **r_filter)
{
	unsigned len;
	struct FILTER *filter;

	*r_filter = (struct FILTER*)malloc(sizeof(struct FILTER));
	memset(*r_filter, 0, sizeof(struct FILTER));
	filter = *r_filter;

	filter->tag = asn1_tag(px,length,r_offset);
	len = asn1_length(frame,px,length,r_offset);

	if (length > *r_offset+len)
		length = *r_offset+len;

	if (0)
	switch (filter->tag) {
	case 0xa0: /* 'and' - SET OF Filter */
	case 0xa1: /* 'or' - SET OF Filter */
		while (*r_offset < length) {
			if (filter->count < 128) {
				process_ldap_filter(frame, px, length, r_offset, &filter->data.filters[filter->count++]);
			} else {
				asn1_tag(px,length,r_offset);
				len = asn1_length(frame,px,length,r_offset);
				*r_offset += len;
			}
		}
		break;
	case 0xa3: /*equalityMatch   - AttributeValueAssertion */
	case 0xa5: /*greaterOrEqual  - AttributeValueAssertion */
	case 0xa6: /*lessOrEqual     - AttributeValueAssertion */
		asn1_string(frame, px, length, r_offset, &filter->data.val.attributeDescription, &filter->data.val.attributeDescription_length);
		asn1_string(frame, px, length, r_offset, &filter->data.val.assertionValue, &filter->data.val.assertionValue_length);
		break;			
	case 0xa4: /*substrings      - SubstringFilter */
	case 0xa7: /*present         - AttributeDescription */
	case 0xa8: /*approxMatch     - AttributeValueAssertion,	default */
	default:
		FRAMERR_BADVAL(frame, "ldap", filter->tag);
		break;
	}

	*r_offset = length;
}

static void process_ldap_search_request(struct Seaper *seap, struct NetFrame *frame, const unsigned char *px, unsigned length, struct LDAP *ldap)
{
	unsigned offset = 0;

	seap;

	asn1_string(frame, px, length, &offset, &ldap->basedn, &ldap->basedn_length);
	ldap->scope = asn1_enumerated(frame, px, length, &offset);
	ldap->dereference = asn1_enumerated(frame, px, length, &offset);
	ldap->size_limit = asn1_integer(frame, px, length, &offset);
	ldap->time_limit = asn1_integer(frame, px, length, &offset);
	ldap->attribute_only = asn1_boolean(frame, px, length, &offset);

	process_ldap_filter(frame, px, length, &offset, &ldap->filter);
}

void process_ldap(struct Seaper *seap, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	unsigned offset=0;
	unsigned outer_length;
	struct LDAP ldap[1];

	memset(ldap, 0, sizeof(ldap[0]));

	/* tag */
	if (asn1_tag(px, length, &offset) != 0x30)
		return;

	/* length */
	outer_length = asn1_length(frame, px, length, &offset);
	if (length > outer_length + offset)
		length = outer_length + offset;

	/* Version */
	ldap->message_id = asn1_integer(frame, px, length, &offset);

	/* PDU */
	ldap->message_type = asn1_tag(px, length, &offset);
	outer_length = asn1_length(frame, px, length, &offset);
	if (length > outer_length + offset)
		length = outer_length + offset;

	switch (ldap->message_type) {
	case 0x63:
		process_ldap_search_request(seap, frame, px+offset, length-offset, ldap);
		break;
	default:
		FRAMERR_BADVAL(frame, "ldap", ldap->message_type);
		break;
	}
}

