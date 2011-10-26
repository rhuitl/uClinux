#ifndef __SP_ASN1_DETECT_H__
#define __SP_ASN1_DETECT_H__


typedef struct s_ASN1_CTXT
{
    int bs_overflow;
    int double_overflow;
    int print;
    int length;
    unsigned int max_length;
    int offset;
    int offset_type;

} ASN1_CTXT;

int Asn1DoDetect(u_int8_t *, u_int16_t, ASN1_CTXT *, u_int8_t *);

#endif
