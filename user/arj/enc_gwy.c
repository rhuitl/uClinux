/*
 * $Id: enc_gwy.c,v 1.1.1.1 2002/03/28 00:02:24 andrew_belov Exp $
 * ---------------------------------------------------------------------------
 * Interface to compression procedures is located here. Any additional code is
 * to be placed here in the compression stubs.
 *
 */

#include "arj.h"

DEBUGHDR(__FILE__)                      /* Debug information block */

void encode_stub(int method)
{
 encode(method);
}

void encode_f_stub()
{
 encode_f();
}
