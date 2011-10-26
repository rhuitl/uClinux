#ident "$Id: faxhng.c,v 4.3 2002/12/16 13:07:53 gert Exp $ Copyright (c) 1993 Gert Doering"

/* faxhng.c - mainly table, translate +FHNG:xxx codes to english text
 */

#include "mgetty.h"

struct t_fhng_table { int i ; char * string; } fhng_table[] = {
	{      -6, "TIMEOUT waiting for modem response (int.)" },
        {      -5, "Unexpected hangup / read() error / write() error (int.)" },
	{      -4, "Unexpected 'ERROR' or 'NO CARRIER' response (int.)" },
	{      -3, "Modem responded 'NO DIALTONE' (int.)" },
	{      -2, "Modem responded 'BUSY' (int.)" },
	{      -1, "Invalid +FPTS:xxx code" },
/*	{     0-9, "CALL PLACEMENT AND TERMINATION" },	*/
	{       0, "Normal and proper end of connection" },
	{       1, "Ring Detect without successful handshake" },
	{       2, "Call aborted, from +FK or AN" },
	{       3, "No Loop Current" },
	{	4, "Ringback detected, no answer (timeout)" },
	{	5, "Ringback detected, answer without CED" },
/*	{   10-19, "TRANSMIT PHASE A & MISCELLANEOUS ERRORS" },	*/
	{      10, "Unspecified Phase A error" },
	{      11, "No Answer (T.30 T1 timeout)" },
/*	{   20-39, "TRANSMIT PHASE B HANGUP CODES" },	*/
	{      20, "Unspecified Transmit Phase B error" },
	{      21, "Remote cannot receive or send" },
	{      22, "COMREC error in transmit Phase B" },
	{      23, "COMREC invalid command received" },
	{      24, "RSPEC error" },
	{      25, "DCS sent three times without response" },
	{      26, "DIS/DTC received 3 times; DCS not recognized" },
	{      27, "Failure to train at 2400 bps or +FMINSP value" },
	{      28, "RSPREC invalid response received" },
/*	{   40-49, "TRANSMIT PHASE C HANGUP CODES" },	*/
	{      40, "Unspecified Transmit Phase C error" },
	{      41, "Unspecified Image format error" },
	{      42, "Image conversion error" },
	{      43, "DTE to DCE data underflow" },
	{      44, "Unrecognized Transparent data command" },
	{      45, "Image error, line length wrong" },
	{      46, "Image error, page length wrong" },
	{      47, "Image error, wrong compression code" },
/*	{   50-69, "TRANSMIT PHASE D HANGUP CODES" },	*/
	{      50, "Unspecified Transmit Phase D error" },
	{      51, "RSPREC error" },
	{      52, "No response to MPS repeated 3 times" },
	{      53, "Invalid response to MPS" },
	{      54, "No response to EOP repeated 3 times" },
	{      55, "Invalid response to EOM" },
	{      56, "No response to EOM repeated 3 times" },
	{      57, "Invalid response to EOM" },
	{      58, "Unable to continue after PIN or PIP" },
/*	{   70-89, "RECEIVE PHASE B HANGUP CODES" },	*/
	{      70, "Unspecified Receive Phase B error" },
	{      71, "RSPREC error" },
	{      72, "COMREC error" },
	{      73, "T.30 T2 timeout, expected page not received" },
	{      74, "T.30 T1 timeout after EOM received" },
/*	{   90-99, "RECEIVE PHASE C HANGUP CODES" },	*/
	{      90, "Unspecified Receive Phase C error" },
	{      91, "Missing EOL after 5 seconds" },
	{      92, "Bad CRC or frame (ECM mode)" },
	{      93, "DCE to DTE buffer overflow" },
	{      94, "Bad CRC or frame (ECM or BFT modes)" },
/*	{ 100-119, "RECEIVE PHASE D HANGUP CODES" },	*/
	{     100, "Unspecified Receive Phase D errors" },
	{     101, "RSPREC invalid response received" },
	{     102, "COMREC invalid response received" },
	{     103, "Unable to continue after PIN or PIP" },
/*	{ 120-255, "RESERVED CODES" },	*/
/* the i4l fax class 2 driver for the DIVA cards uses 120-151 */
	{     128, "DIVA: all rates failed" },
	{     129, "DIVA: too many trains" },
	{     130, "DIVA: receive corrupted" },
	{     131, "DIVA: unexpected disconnect" },
	{     141, "DIVA: scan line too long" } 
	};

char * fax_strerror _P1( (fhng), int fhng )
{
    int i;
    for ( i=0; i < sizeof( fhng_table ) / sizeof( fhng_table[0] ); i++ )
    {
	if ( fhng_table[i].i == fhng )
	{
	    return fhng_table[i].string;
	}
    }
    return "unknown +FHNG error code";
}
