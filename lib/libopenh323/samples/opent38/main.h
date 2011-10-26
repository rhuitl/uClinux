/*
 * main.h
 *
 * Version number header file for simple OpenH323 sample T.38 transmitter.
 *
 * Copyright (c) 2001 Equivalence Pty. Ltd.
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
 * $Log: main.h,v $
 * Revision 1.5  2002/04/17 03:51:43  robertj
 * Fixed correct function override, thanks Suk Tong Hoon
 *
 * Revision 1.4  2001/12/22 03:36:02  robertj
 * Added create protocol function to H323Connection.
 *
 * Revision 1.3  2001/12/20 04:10:06  robertj
 * More T.38 testing
 *
 * Revision 1.2  2001/12/13 11:07:03  robertj
 * More implementation
 *
 */


#ifndef _T38App_MAIN_H
#define _T38App_MAIN_H

#include <h323.h>
#include "t38proto.h"


class T38App : public PProcess
{
  PCLASSINFO(T38App, PProcess)
  public:
    T38App();
    void Main();
};


class T38EndPoint : public H323EndPoint
{
  PCLASSINFO(T38EndPoint, H323EndPoint);
	
  public:
    T38EndPoint(BOOL rx);

    virtual OpalT38Protocol * CreateT38ProtocolHandler(
      const H323Connection & connection
    ) const;
};


#endif // _T38App_MAIN_H


// End of File ///////////////////////////////////////////////////////////////
