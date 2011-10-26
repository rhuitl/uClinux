/*
 * main.h
 *
 * PWLib application header file for XMLRPCApp
 *
 * Copyright 2002 Equivalence
 *
 * $Log: main.h,v $
 * Revision 1.1  2002/03/26 07:05:28  craigs
 * Initial version
 *
 */

#ifndef _XMLRPCApp_MAIN_H
#define _XMLRPCApp_MAIN_H




class XMLRPCApp : public PProcess
{
  PCLASSINFO(XMLRPCApp, PProcess)

  public:
    XMLRPCApp();
    void Main();
};


#endif  // _XMLRPCApp_MAIN_H


// End of File ///////////////////////////////////////////////////////////////
