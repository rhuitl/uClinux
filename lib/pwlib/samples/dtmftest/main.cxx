/*
 * main.cxx
 *
 * PWLib application source file for dtmftest
 *
 * Main program entry point.
 *
 * Copyright (c) 2003 Equivalence Pty. Ltd.
 *
 * The contents of this file are subject to the Mozilla Public License
 * Version 1.0 (the "License"); you may not use this file except in
 * compliance with the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS"
 * basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See
 * the License for the specific language governing rights and limitations
 * under the License.
 *
 * The Original Code is Portable Windows Library.
 *
 * The Initial Developer of the Original Code is Equivalence Pty. Ltd.
 *
 * Contributor(s): ______________________________________.
 *
 * $Log: main.cxx,v $
 * Revision 1.5  2005/11/30 12:47:40  csoutheren
 * Removed tabs, reformatted some code, and changed tags for Doxygen
 *
 * Revision 1.4  2005/07/21 13:09:43  rogerhardiman
 * Fix typo in help
 *
 * Revision 1.3  2004/09/10 22:33:31  dereksmithies
 * Calculate time required to do the decoding of the dtmf symbol.
 *
 * Revision 1.2  2004/09/10 04:31:57  dereksmithies
 * Add code to calculate the detection rate.
 *
 * Revision 1.1  2004/09/10 01:59:35  dereksmithies
 * Initial release of program to test Dtmf creation and detection.
 *
 *
 */

#include "precompile.h"
#include "main.h"
#include "version.h"


PCREATE_PROCESS(DtmfTest);

#include  <ptclib/dtmf.h>
#include  <ptclib/random.h>



DtmfTest::DtmfTest()
  : PProcess("Equivalence", "dtmftest", MAJOR_VERSION, MINOR_VERSION, BUILD_TYPE, BUILD_NUMBER)
{
}


void DtmfTest::Main()
{
  PArgList & args = GetArguments();

  args.Parse(
             "h-help."               "-no-help."
             "s-samples:"            "-no-numsamples."
             "n-noise:"              "-no-noise."
#if PTRACING
             "o-output:"             "-no-output."
             "t-trace."              "-no-trace."
#endif
             "v-version."
  );

#if PTRACING
  PTrace::Initialise(args.GetOptionCount('t'),
                     args.HasOption('o') ? (const char *)args.GetOptionString('o') : NULL,
         PTrace::Blocks | PTrace::Timestamp | PTrace::Thread | PTrace::FileAndLine);
#endif

  if (args.HasOption('v')) {
    cout << "Product Name: " << GetName() << endl
         << "Manufacturer: " << GetManufacturer() << endl
         << "Version     : " << GetVersion(TRUE) << endl
         << "System      : " << GetOSName() << '-'
         << GetOSHardware() << ' '
         << GetOSVersion() << endl;
    return;
  }

  if (args.HasOption('h')) {
    PError << "Available options are: " << endl         
           << endl
           <<    "Generates 16 dtmf symbols, of length sample size with noise level\n"
           <<    " and then decodes them. \n"
           <<    " Simulation is done at 8000Hz, or 8khz, 16 bit integers.\n"
           <<    "A report on the success (or not) is reported\n"
           << endl
           <<    "-h or --help          : print this help message.\n"
           <<    "-s or --samples #     : number of samples to use (ms).\n"
           <<    "-n or --noise   #     : Peak noise level (0..10000)\n"
#if PTRACING
           <<    "-o or --output file   : file name for output of log messages\n"       
           <<    "-t or --trace         : degree of verbosity in error log (more times for more detail)\n"     
#endif
           <<    "-v or --version       : report version information\n"
           << endl
           << " e.g. ./dtmftest -s 60 -n 100    \n"
           << "                to generate 60ms long samples, with a signal noise ratio of 100\n"
           << endl << endl;
    return;
  }
  
  
  PINDEX samples;
  if (args.HasOption('s'))
    samples = args.GetOptionString('s').AsInteger();
  else
    samples = 80;

  PINDEX noise;
  if (args.HasOption('n'))
    noise = args.GetOptionString('n').AsInteger();
  else
    noise = 0;

  samples = PMAX(PMIN(200 * 1000, samples), 10);
  noise   = PMAX(PMIN(10000, noise), 0);

  cout << "Sample section  is " << samples << " ms long." << endl;
  cout << "Peak noise magnitude is " << noise << endl;

  PINDEX i;
  PDTMFDecoder decoder;
  PBYTEArray   noiseSignal(samples * 8 * 2);

  if (noise > 0) 
    for (i = 0; i < noiseSignal.GetSize(); i+=2) {
      PINDEX noiseValue = (WORD) PRandom::Number() % noise; 
      noiseSignal[i] = (BYTE)(noiseValue & 0xff);
      noiseSignal[i+1] = (BYTE)(noiseValue >> 8);
    }

  PBYTEArray   result(samples * 8 * 2);

  int nCorrect = 0;
  for (i = 0; i < 16; i++) {
    PDTMFEncoder encoder;
    PString symbol = encoder.DtmfChar(i);
    encoder.AddTone(symbol, samples);

    for (PINDEX j = 0; j < encoder.GetSize(); j+=2) {
      int  signal = ((int)encoder[j]) + ((int)encoder[j + 1] << 8);
      signal       += noiseSignal[j] + (noiseSignal[j + 1] << 8);
      result[j]     = (BYTE)(signal & 0xff);
      result[j + 1] = (BYTE)(signal >> 8);
    }

    PTime startTime;
    PString tones = decoder.Decode(result.GetPointer(), result.GetSize() );
    PTimeInterval elapsed = PTime() - startTime;

    if (tones.IsEmpty())
      tones = " ";
    cout << "Test : " << symbol << " ---> " << tones << "    ";

    if (symbol == tones) {
      cout << "Good";
      nCorrect++;
    } else {
      cout << "Fail";
    }

    cout << "       decode time : " << elapsed.GetInterval() << " millisecs" << endl;
  }

  cout << endl << "Test run complete. Correctly interpreted " << (int)((nCorrect / 0.16) + 0.5) << "%" << endl;
}

// End of File ///////////////////////////////////////////////////////////////
