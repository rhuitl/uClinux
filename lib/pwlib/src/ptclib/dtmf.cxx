/*
 * ----------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * <phk@FreeBSD.org> wrote this file.  As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return.   Poul-Henning Kamp
 * ----------------------------------------------------------------------------
 *
 * Extract DTMF signals from 16 bit PCM audio
 *
 * Originally written by Poul-Henning Kamp <phk@freebsd.org>
 * Made into a C++ class by Roger Hardiman <roger@freebsd.org>, January 2002
 *
 * $Log: dtmf.cxx,v $
 * Revision 1.14  2005/11/30 12:47:41  csoutheren
 * Removed tabs, reformatted some code, and changed tags for Doxygen
 *
 * Revision 1.13  2005/01/25 06:35:27  csoutheren
 * Removed warnings under MSVC
 *
 * Revision 1.12  2004/11/17 10:13:14  csoutheren
 * Fixed compilation with gcc 4.0.0
 *
 * Revision 1.11  2004/09/09 23:50:49  csoutheren
 * Fixed problem with duplicate definition of sinetab causing problems
 *
 * Revision 1.10  2004/09/09 05:23:38  dereksmithies
 * Add utility function to report on dtmf characters used.
 *
 * Revision 1.9  2004/09/09 04:22:46  csoutheren
 * Added sine table for DTMF encoder
 *
 * Revision 1.8  2004/09/09 04:00:01  csoutheren
 * Added DTMF encoding functions
 *
 * Revision 1.7  2003/03/17 07:39:25  robertj
 * Fixed possible invalid value causing DTMF detector to crash.
 *
 * Revision 1.6  2002/02/20 02:59:34  yurik
 * Added end of line to trace statement
 *
 * Revision 1.5  2002/02/12 10:21:56  rogerh
 * Stop sending '?' when a bad DTMF tone is detected.
 *
 * Revision 1.4  2002/01/24 11:14:45  rogerh
 * Back out robert's change. It did not work (no sign extending)
 * and replace it with a better solution which should be happy on both big
 * endian and little endian systems.
 *
 * Revision 1.3  2002/01/24 10:40:17  rogerh
 * Add version log
 *
 *
 */

#ifdef __GNUC__
#pragma implementation "dtmf.h"
#endif

#include <ptlib.h>
#include <ptclib/dtmf.h>

#include <math.h>

/* Integer math scaling factor */
#define FSC (1<<12)

/* This is the Q of the filter (pole radius) */
#define POLRAD .99

#define P2 ((int)(POLRAD*POLRAD*FSC))



PDTMFDecoder::PDTMFDecoder()
{
  // Initialise the class
  int i,kk;
  for (kk = 0; kk < 8; kk++) {
    y[kk] = h[kk] = k[kk] = 0;
  }

  nn = 0;
  ia = 0;
  so = 0;

  for (i = 0; i < 256; i++) {
    key[i] = '?';
  }

  /* We encode the tones in 8 bits, translate those to symbol */
  key[0x11] = '1'; key[0x12] = '4'; key[0x14] = '7'; key[0x18] = '*';
  key[0x21] = '2'; key[0x22] = '5'; key[0x24] = '8'; key[0x28] = '0';
  key[0x41] = '3'; key[0x42] = '6'; key[0x44] = '9'; key[0x48] = '#';
  key[0x81] = 'A'; key[0x82] = 'B'; key[0x84] = 'C'; key[0x88] = 'D';

  /* The frequencies we're trying to detect */
  /* These are precalculated to save processing power */
  /* static int dtmf[8] = {697, 770, 852, 941, 1209, 1336, 1477, 1633}; */
  /* p1[kk] = (-cos(2 * 3.141592 * dtmf[kk] / 8000.0) * FSC) */
  p1[0] = -3497; p1[1] = -3369; p1[2] = -3212; p1[3] = -3027;
  p1[4] = -2384; p1[5] = -2040; p1[6] = -1635; p1[7] = -1164;
}


PString PDTMFDecoder::Decode(const void *buf, PINDEX bytes)
{
  int x;
  int s, kk;
  int c, d, f, n;
  short *buffer = (short *)buf;

  PINDEX numSamples = bytes >> 1;

  PString keyString;

  PINDEX pos;
  for (pos = 0; pos < numSamples; pos++) {

    /* Read (and scale) the next 16 bit sample */
    x = ((int)(*buffer++)) / (32768/FSC);

    /* Input amplitude */
    if (x > 0)
      ia += (x - ia) / 128;
    else
      ia += (-x - ia) / 128;

    /* For each tone */
    s = 0;
    for(kk = 0; kk < 8; kk++) {

      /* Turn the crank */
      c = (P2 * (x - k[kk])) / FSC;
      d = x + c;
      f = (p1[kk] * (d - h[kk])) / FSC;
      n = x - k[kk] - c;
      k[kk] = h[kk] + f;
      h[kk] = f + d;

      /* Detect and Average */
      if (n > 0)
        y[kk] += (n - y[kk]) / 64;
      else
        y[kk] += (-n - y[kk]) / 64;

      /* Threshold */
      if (y[kk] > FSC/10 && y[kk] > ia)
        s |= 1 << kk;
    }

    /* Hysteresis and noise supressor */
    if (s != so) {
      nn = 0;
      so = s;
    } else if (nn++ == 520 && s < 256 && key[s] != '?') {
      PTRACE(3,"DTMF\tDetected '" << key[s] << "' in PCM-16 stream");
      keyString += key[s];
    }
  }
  return keyString;
}

////////////////////////////////////////////////////////////////////////////////////////////

//
//  implement a PCM tone generator
//
//  For reference, the US tones are (as indictated by http://www.elexp.com/t_tele.htm)
//
//   Dial Tone 350 Hz + 440 Hz Continuous 
//   Ring Back 440 Hz + 480 Hz ON 2.0, OFF 4.0 seconds 
//   Busy 480 Hz + 620 Hz On 0.5, OFF 0.5 seconds 
//

// this code is based on code copied from http://www-users.cs.york.ac.uk/~fisher/telecom/tones/teletones.C


#define   DTMF_LEN  100

#ifndef M_PI
#define M_PI        3.1415926
#endif

#define TWOPI        (2.0 * M_PI)
#define MAXSTR       512
#define SAMPLERATE   8000
#define SINEBITS     11
#define SINELEN       (1 << SINEBITS)
#define TWO32        4294967296.0  /* 2^32 */


static double amptab[2] = { 8191.75, 16383.5 };

static inline int ifix(double x) 
{ 
  return (x >= 0.0) ? (int) (x+0.5) : (int) (x-0.5); 
}

// given frequency f, return corresponding phase increment 
static inline int phinc(double f)
{ 
  return ifix(TWO32 * f / (double) SAMPLERATE);
}

static char dtmfSymbols[16] = {
  '0',
  '1',
  '2',
  '3',
  '4',
  '5',
  '6',
  '7',
  '8',
  '9',
  'A',
  'B',
  'C',
  'D',
  '*',
  '#'
};

char PDTMFEncoder::DtmfChar(PINDEX i)
{
  PAssert(i < 16, "Only 16 dtmf symbols. Index too large");

  return dtmfSymbols[i];
}




// DTMF frequencies as per http://www.commlinx.com.au/DTMF_frequencies.htm

static double dtmfFreqs[16][2] = {
  { 941.0, 1336.0 },  // 0
  { 697.0, 1209.0 },  // 1
  { 697.0, 1336.0 },  // 2
  { 697.0, 1477.0 },  // 3
  { 770.0, 1209.0 },  // 4
  { 770.0, 1336.0 },  // 5
  { 770.0, 1477.0 },  // 6
  { 852.0, 1209.0 },  // 7
  { 852.0, 1336.0 },  // 8
  { 852.0, 1477.0 },  // 9
  { 697.0, 1633.0 },  // A
  { 770.0, 1633.0 },  // B
  { 852.0, 1633.0 },  // C
  { 941.0, 1633.0 },  // D
  { 941.0, 1209.0 },  // *
  { 941.0, 1477.0 }   // #
};

////////////////////////////////////////////////////////////////////////

double PDTMFEncoder::sinetab[1 << 11];

PMutex & PDTMFEncoder::GetMutex()
{
  static PMutex mutex;
  return mutex;
}

void PDTMFEncoder::MakeSineTable()
{ 
  PWaitAndSignal m(GetMutex());
  static BOOL sineTabInit = FALSE;

  if (!sineTabInit) {
    for (int k = 0; k < SINELEN; k++) { 
      double th = TWOPI * (double) k / (double) SINELEN;
      double v = sin(th);
      sinetab[k] = v;
    }
    sineTabInit = TRUE;
  }
}

void PDTMFEncoder::AddTone(char _digit, unsigned len)
{
  char digit = (char)toupper(_digit);
  if ('0' <= digit && digit <= '9')
    digit = (char)(digit - '0');

  else if ('A' <= digit && digit <= 'D')
    digit = (char)(digit + 10 - 'A');

  else if (digit == '*')
    digit = 14;

  else if (digit == '#')
    digit = 15;

  else
    return;

  AddTone(dtmfFreqs[(int)digit][0], dtmfFreqs[(int)digit][1], len);
}

void PDTMFEncoder::AddTone(const PString & str, unsigned len)
{
  PINDEX i;
  for (i = 0; i < str.GetLength(); i++)
    AddTone(str[i], len);
}

void PDTMFEncoder::AddTone(double f1, double f2, unsigned ms)
{
  int ak = 0;

  MakeSineTable();

  PINDEX dataPtr = GetSize();

  double amp = amptab[ak];
  int phinc1 = phinc(f1), phinc2 = phinc(f2);
  int ns = ms * (SAMPLERATE/1000);
  unsigned int ptr1 = 0, ptr2 = 0;

  for (int n = 0; n < ns; n++) { 

    double val = amp * (sine(ptr1) + sine(ptr2));
    int ival = ifix(val);
    if (ival < -32768)
      ival = -32768;
    else if (val > 32767) 
      ival = 32767;

    if (dataPtr == GetSize()) 
      SetSize(GetSize() + 1024);

    (*this)[dataPtr++] = (BYTE)(ival & 0xff);
    (*this)[dataPtr++] = (BYTE)(ival >> 8);

    ptr1 += phinc1; 
    ptr2 += phinc2;
  }

  SetSize(dataPtr);
}

////////////////////////////////////////////////////////////////////////////
