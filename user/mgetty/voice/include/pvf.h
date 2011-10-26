/*
 * pvf.h
 *
 * Contains the constants and function prototypes for the pvf tools
 *
 * $Id: pvf.h,v 1.7 2001/05/14 09:52:29 marcs Exp $
 *
 */

#include "wav.h"

/*
 * Constants
 */

/*
 * Blocksize for reading voice files into memory
 */

#define BLOCK_SIZE 0x10000

/*
 * Decimal point shift for fixed-point arithmetic
 */

#define SHIFT 12
#define ONE   (1 << SHIFT)

/*
 * Structure for handling pvf files
 */

typedef struct
     {
     int ascii;
     int channels;
     int speed;
     int nbits;
     int (*read_pvf_data) (FILE *fd_in);
     void (*write_pvf_data) (FILE *fd_out, int data);
     } pvf_header;

/*
 * Structure for handling bit read and write operations
 */

typedef struct
     {
     int data;
     int nleft;
     } state_t;

extern rmd_header init_rmd_header;
extern pvf_header init_pvf_header;
extern state_t init_state;
extern int bitmask[17];

/*
 * Functions
 */

extern unsigned char linear2ulaw (int sample);
extern int ulaw2linear (unsigned char ulawbyte);

extern int read_rmd_header (FILE *fd_in, rmd_header *header_in);
extern int write_rmd_header (FILE *fd_out, rmd_header *header_out);

extern int read_pvf_header (FILE *fd_in, pvf_header *header_in);
extern int write_pvf_header (FILE *fd_out, pvf_header *header_out);

extern int read_bits (FILE *fd_in, state_t *state, int nbits);
extern void write_bits (FILE *fd_out, state_t *state, int nbits, int data);
extern int read_bits_reverse (FILE *fd_in, state_t *state, int nbits);
extern void write_bits_reverse (FILE *fd_out, state_t *state, int nbits,
 int data);

extern int pvftorockwell (FILE *fd_in, FILE *fd_out, int nbits,
 pvf_header *header_in);
extern int rockwelltopvf (FILE *fd_in, FILE *fd_out, int nbits,
 pvf_header *header_out);

extern int pvftorockwellpcm (FILE *fd_in, FILE *fd_out, int nbits,
 pvf_header *header_in);
extern int rockwellpcmtopvf (FILE *fd_in, FILE *fd_out, int nbits,
 pvf_header *header_out);


extern int pvftozyxel (FILE *fd_in, FILE *fd_out, int nbits,
 pvf_header *header_in);
extern int zyxeltopvf (FILE *fd_in, FILE *fd_out, int nbits,
 pvf_header *header_out);

extern int pvftozo56k (FILE *fd_in, FILE *fd_out, pvf_header *header_in);
extern int zo56ktopvf (FILE *fd_in, FILE *fd_out, pvf_header *header_out);

extern int pvftousr (FILE *fd_in, FILE *fd_out, int compression,
 pvf_header *header_in);
extern int usrtopvf (FILE *fd_in, FILE *fd_out, int compression,
 pvf_header *header_out);

extern int pvftoimaadpcm (FILE *fd_in, FILE *fd_out, pvf_header *header_in);
extern int imaadpcmtopvf (FILE *fd_in, FILE *fd_out, pvf_header *header_out);

extern int pvftovoc (FILE *fd_in, FILE *fd_out, pvf_header *header_in);
extern int voctopvf (FILE *fd_in, FILE *fd_out, pvf_header *header_out);

extern int pvftolin (FILE *fd_in, FILE *fd_out, pvf_header *header_in,
 int is_signed, int bits16, int intel);
extern int lintopvf (FILE *fd_in, FILE *fd_out, pvf_header *header_out,
 int is_signed, int bits16, int intel);

extern int pvftoulaw (FILE *fd_in, FILE *fd_out, pvf_header *header_in);
extern int ulawtopvf (FILE *fd_in, FILE *fd_out, pvf_header *header_out);
extern int pvftoalaw (FILE *fd_in, FILE *fd_out, pvf_header *header_in);
extern int alawtopvf (FILE *fd_in, FILE *fd_out, pvf_header *header_out);
#define pvftobasic pvftoulaw
#define basictopvf ulawtopvf

#define SND_FORMAT_MULAW_8    1
#define SND_FORMAT_LINEAR_8   2
#define SND_FORMAT_LINEAR_16  3
#define SND_FORMAT_ALAW_8     27

extern int pvftoau (FILE *fd_in, FILE *fd_out, pvf_header *header_in,
 int dataFormat);
extern int autopvf (FILE *fd_in, FILE *fd_out, pvf_header *header_out);

extern int pvftowav (FILE *fd_in, FILE *fd_out, pvf_header *header_in,
 int wav_bits);
extern int wavtopvf (FILE *fd_in, FILE *fd_out, pvf_header *header_out);

extern int pvffft (FILE *fd_in, pvf_header *header_in, int skip,
 int sample_size, double threshold, int vgetty_pid, int display);
