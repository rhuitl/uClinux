/*
 * pnat.h
 *
 * NAT Strategy support for Portable Windows Library.
 *
 * Virteos is a Trade Mark of ISVO (Asia) Pte Ltd.
 *
 * Copyright (c) 2004 ISVO (Asia) Pte Ltd. All Rights Reserved.
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
 *
 * The Original Code is derived from and used in conjunction with the 
 * OpenH323 Project (www.openh323.org/)
 *
 * The Initial Developer of the Original Code is ISVO (Asia) Pte Ltd.
 *
 *
 * Contributor(s): ______________________________________.
 *
 * $Log: pnat.h,v $
 * Revision 1.3.2.1  2006/01/27 03:43:24  csoutheren
 * Backported changes to CVS head into Phobos
 *
 * Revision 1.4  2006/01/26 03:23:41  shorne
 * Fix compile error when merging code
 *
 * Revision 1.3  2005/11/30 12:47:37  csoutheren
 * Removed tabs, reformatted some code, and changed tags for Doxygen
 *
 * Revision 1.2  2005/07/13 11:15:14  csoutheren
 * Backported NAT abstraction files from isvo branch
 *
 * Revision 1.1.2.1  2005/04/25 13:23:19  shorne
 * Initial version
 *
 *
*/

#include <ptlib.h>
#include <ptlib/sockets.h>

#ifndef P_NATMETHOD
#define P_NATMETHOD

/** PNatMethod
    Base Network Address Traversal Method class
    All NAT Traversal Methods are derived off this class. 
    There are quite a few methods of NAT Traversal. The 
    only purpose of this class is to provide a common 
    interface. It is intentionally minimalistic.
*/
class PNatMethod  : public PObject
{
  PCLASSINFO(PNatMethod,PObject);

public:

  /**@name Construction */
  //@{
  /** Default Contructor
  */
  PNatMethod();

  /** Deconstructor
  */
  ~PNatMethod();
  //@}

  /**@name General Functions */
  //@{

  /**  GetExternalAddress
    Get the acquired External IP Address.
  */
   virtual BOOL GetExternalAddress(
      PIPSocket::Address & externalAddress, /// External address of router
      const PTimeInterval & maxAge = 1000   /// Maximum age for caching
   ) =0;

  /**  CreateSocketPair
    Create the UDP Socket pair
  */
   virtual BOOL CreateSocketPair(
      PUDPSocket * & socket1,
      PUDPSocket * & socket2
   ) =0;

  /**Returns whether the Nat Method is ready and available in
     assisting in NAT Traversal. The principal is function is
     to allow the EP to detect various methods and if a method
     is detected then this method is available for NAT traversal
     The Order of adding to the PNstStrategy determines which method
     is used
  */
   virtual BOOL IsAvailable() { return FALSE; };

    /**Set the port ranges to be used on local machine.
       Note that the ports used on the NAT router may not be the same unless
       some form of port forwarding is present.

       If the port base is zero then standard operating system port allocation
       method is used.

       If the max port is zero then it will be automatically set to the port
       base + 99.
      */
   virtual void SetPortRanges(
      WORD portBase,          /// Single socket port number base
      WORD portMax = 0,       /// Single socket port number max
      WORD portPairBase = 0,  /// Socket pair port number base
      WORD portPairMax = 0    /// Socket pair port number max
   );
  //@}

protected:
  struct PortInfo {
      PMutex mutex;
      WORD   basePort;
      WORD   maxPort;
      WORD   currentPort;
    } singlePortInfo, pairedPortInfo;

};

/////////////////////////////////////////////////////////////

PLIST(PNatList, PNatMethod);

/////////////////////////////////////////////////////////////

/** PNatStrategy
  The main container for all
  NAT traversal Strategies. 
*/

class PNatStrategy : public PObject
{
  PCLASSINFO(PNatStrategy,PObject);

public :

  /**@name Construction */
  //@{
  /** Default Contructor
  */
  PNatStrategy();

  /** Deconstructor
  */
  ~PNatStrategy();
  //@}

  /**@name Method Handling */
  //@{
  /** AddMethod
    This function is used to add the required NAT
    Traversal Method. The Order of Loading is important
    The first added has the highest priority.
  */
  void AddMethod(PNatMethod * method);

  /** GetMethod
    This function retrieves the first available NAT
    Traversal Method. If no available NAT Method is found
    then NULL is returned. 
  */
  PNatMethod * GetMethod();

    /**Set the port ranges to be used on local machine.
       Note that the ports used on the NAT router may not be the same unless
       some form of port forwarding is present.

       If the port base is zero then standard operating system port allocation
       method is used.

       If the max port is zero then it will be automatically set to the port
       base + 99.
      */
    void SetPortRanges(
      WORD portBase,          /// Single socket port number base
      WORD portMax = 0,       /// Single socket port number max
      WORD portPairBase = 0,  /// Socket pair port number base
      WORD portPairMax = 0    /// Socket pair port number max
    );
  //@}

private:
  PNatList natlist;
};

#endif
