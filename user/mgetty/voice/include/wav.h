/*
 * wav.h
 *
 * This file includes the definitions for the wav file format.
 *
 * $Id: wav.h,v 1.4 1998/09/09 21:06:40 gert Exp $
 *
 */

#define   WAVE_FORMAT_UNKNOWN      (0x0000)
#define   WAVE_FORMAT_PCM          (0x0001)
#define   WAVE_FORMAT_ADPCM        (0x0002)
#define   WAVE_FORMAT_ALAW         (0x0006)
#define   WAVE_FORMAT_MULAW        (0x0007)
#define   WAVE_FORMAT_OKI_ADPCM    (0x0010)
#define   WAVE_FORMAT_DIGISTD      (0x0015)
#define   WAVE_FORMAT_DIGIFIX      (0x0016)
#define   IBM_FORMAT_MULAW         (0x0101)
#define   IBM_FORMAT_ALAW          (0x0102)
#define   IBM_FORMAT_ADPCM         (0x0103)

/*
 * Handler structure for each format.
 */

typedef struct format
     {
     char **names;  /* file type names */
     int  flags;         /* details about file type */
     int  (*startread)();
     int  (*read)();
     int  (*stopread)();
     int  (*startwrite)();
     int  (*write)();
     int  (*stopwrite)();
     } format_t;

extern format_t formats[];

/* Signal parameters */

struct  signalinfo
     {
     long      rate;          /* sampling rate */
     int       size;          /* word length of data */
     int       style;         /* format of sample numbers */
     int       channels; /* number of sound channels */
     };

/* Loop parameters */

struct  loopinfo
     {
     int       start;         /* first sample */
     int       length;        /* length */
     int       count;         /* number of repeats, 0=forever */
     int       type;          /* 0=no, 1=forward, 2=forward/back */
     };

/* Instrument parameters */

/* vague attempt at generic information for sampler-specific info */

struct  instrinfo
     {
     char      MIDInote; /* for unity pitch playback */
     char      MIDIlow, MIDIhi;/* MIDI pitch-bend range */
     char      loopmode; /* semantics of loop data */
     char      nloops;        /* number of active loops */
     unsigned char  smpte[4]; /* SMPTE offset (hour:min:sec:frame) */
                         /* this is a film audio thing */
     };

#define MIDI_UNITY 60         /* MIDI note number to play sample at unity */

/* Loop modes */
#define LOOP_NONE          0
#define LOOP_8             1  /* 8 loops: don't know ?? */
#define LOOP_SUSTAIN_DECAY 2  /* AIFF style: one sustain & one decay loop */

/*
 *  Format information for input and output files.
 */

#define   PRIVSIZE  100

#define NLOOPS      8

struct soundstream
     {
     struct    signalinfo info;    /* signal specifications */
     struct  instrinfo instr; /* instrument specification */
     struct  loopinfo loops[NLOOPS];    /* Looping specification */
     char swap;               /* do byte- or word-swap */
     char seekable;      /* can seek on this file */
     char *filename;          /* file name */
     char *filetype;          /* type of file */
     char *comment;      /* comment string */
     FILE *fp;           /* File stream pointer */
     format_t *h;             /* format struct for this file */
     double    priv[PRIVSIZE/8];   /* format's private data area */
     };

extern struct soundstream informat, outformat;
typedef struct soundstream *ft_t;

/* flags field */
#define FILE_STEREO 1    /* does file format support stereo? */
#define FILE_LOOPS  2    /* does file format support loops? */
#define FILE_INSTR  4    /* does file format support instrument specificications? */

/* Size field */
#define   BYTE 1
#define   WORD 2
#define   LONG 4
#define   FLOAT     5
#define DOUBLE 6
#define IEEE   7         /* IEEE 80-bit floats.  Is it necessary? */

/* Style field */
#define UNSIGNED    1    /* unsigned linear: Sound Blaster */
#define SIGN2       2    /* signed linear 2's comp: Mac */
#define   ULAW      3    /* U-law signed logs: US telephony, SPARC */
#define ALAW        4    /* A-law signed logs: non-US telephony */

extern char *sizes[], *styles[];

/*
 * Handler structure for each effect.
 */

typedef struct
     {
     char *name;              /* effect name */
     int  flags;              /* this and that */
     int  (*getopts)();       /* process arguments */
     int  (*start)();         /* start off effect */
     int  (*flow)();          /* do a buffer */
     int  (*drain)();         /* drain out at end */
     int  (*stop)();          /* finish up effect */
     } effect_t;

extern effect_t effects[];

#define   EFF_CHAN  1         /* Effect can mix channels up/down */
#define EFF_RATE    2         /* Effect can alter data rate */
#define EFF_MCHAN   4         /* Effect can handle multi-channel */
#define EFF_REPORT  8         /* Effect does nothing */

struct effect
     {
     char      *name;         /* effect name */
     struct signalinfo ininfo;     /* input signal specifications */
     struct loopinfo   loops[8];   /* input loops  specifications */
     struct instrinfo  instr; /* input instrument  specifications */
     struct signalinfo outinfo;    /* output signal specifications */
     effect_t  *h;       /* effects driver */
     long      *obuf;         /* output buffer */
     long      odone, olen;   /* consumed, total length */
     double         priv[PRIVSIZE];     /* private area for effect */
     };

typedef struct effect *eff_t;
