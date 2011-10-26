#ifndef SF_THRESHOLD
#define SF_THRESHOLD

#include "sfthd.h"

void ParseThreshold2( THDX_STRUCT * thdx, char * s );
void ProcessThresholdOptions( char * args);
void ParseSFThreshold( FILE * fp, char * rule );
void ParseSFSuppress( FILE * fp, char * rule );

int  sfthreshold_init( void );
void sfthreshold_reset(void);

int  sfthreshold_create( THDX_STRUCT * thdx  );
int  sfthreshold_test( unsigned gen_id,unsigned  sig_id, unsigned sip, unsigned dip, long  curtime );

void print_thresholding();

#endif
