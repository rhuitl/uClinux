/*
 * main.h
 *
 * PWLib application header file for vxmltest
 *
 * Copyright 2002 Equivalence
 *
 * $Log: main.h,v $
 * Revision 1.2  2004/06/02 08:30:22  csoutheren
 * Tweaks to avoid some problems with reading single bytes from a PCM stream
 *
 * Revision 1.1  2002/08/06 05:26:33  craigs
 * Initial version
 *
 */

#ifndef _Vxmltest_MAIN_H
#define _Vxmltest_MAIN_H

class PVXMLSession;

class Vxmltest : public PProcess
{
  PCLASSINFO(Vxmltest, PProcess)

  public:
    Vxmltest();
    void Main();
    PDECLARE_NOTIFIER(PThread, Vxmltest, InputThread);

  protected:
    BOOL inputRunning;
    PVXMLSession * vxml;
};


#endif  // _Vxmltest_MAIN_H


// End of File ///////////////////////////////////////////////////////////////
