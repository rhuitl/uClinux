/*
 * snmpserv.cxx
 *
 * SNMP Server (agent) class
 *
 * Portable Windows Library
 *
 * Copyright (c) 1993-2002 Equivalence Pty. Ltd.
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
 * $Log: snmpserv.cxx,v $
 * Revision 1.4  2002/11/06 22:47:25  robertj
 * Fixed header comment (copyright etc)
 *
 * Revision 1.3  1998/11/30 04:52:09  robertj
 * New directory structure
 *
 * Revision 1.2  1998/09/23 06:22:42  robertj
 * Added open source copyright license.
 *
 * Revision 1.1  1996/09/14 13:02:18  robertj
 * Initial revision
 *
 */

#include <ptlib.h>
#include <ptclib/psnmp.h>


BOOL PSNMPServer::SendGetResponse (PSNMPVarBindingList &)
{
  PAssertAlways("SendGetResponse not yet implemented");
  return GenErr;
}


void PSNMPServer::OnGetRequest (PSNMPVarBindingList &)
{
}


void PSNMPServer::OnGetNextRequest (PSNMPVarBindingList &)
{
}


void PSNMPServer::OnSetRequest (PSNMPVarBindingList &)
{
}


BOOL PSNMP::DecodeTrap(const PBYTEArray & readBuffer,
                                       PINDEX & version,
                                      PString & community,
                                      PString & enterprise,
                           PIPSocket::Address & address,
                                       PINDEX & genericTrapType,
                                      PINDEX  & specificTrapType,
                                 PASNUnsigned & timeTicks,
                          PSNMPVarBindingList & varsOut)
{
  // parse the response
  PASNSequence response(readBuffer);
  PINDEX seqLen = response.GetSize();

  // check PDU
  if (seqLen != 3 ||
      response[0].GetType() != PASNObject::Integer ||
      response[1].GetType() != PASNObject::String ||
      response[2].GetType() != PASNObject::Choice) 
    return FALSE;

  // check the PDU data
  const PASNSequence & rPduData = response[2].GetSequence();
  seqLen = rPduData.GetSize();
  if (seqLen != 6 ||
      rPduData.GetChoice()  != Trap ||
      rPduData[0].GetType() != PASNObject::ObjectID ||
      rPduData[1].GetType() != PASNObject::IPAddress ||
      rPduData[2].GetType() != PASNObject::Integer ||
      rPduData[3].GetType() != PASNObject::Integer ||
      rPduData[4].GetType() != PASNObject::TimeTicks ||
      rPduData[5].GetType() != PASNObject::Sequence) 
    return FALSE;

  version          = response[0].GetInteger();
  community        = response[1].GetString();
  enterprise       = rPduData[0].GetString();
  address          = rPduData[1].GetIPAddress();
  genericTrapType  = rPduData[2].GetInteger();
  specificTrapType = rPduData[3].GetInteger();
  timeTicks        = rPduData[4].GetUnsigned();

  // check the variable bindings
  const PASNSequence & rBindings = rPduData[5].GetSequence();
  PINDEX bindingCount = rBindings.GetSize();

  // create the return list
  for (PINDEX i = 0; i < bindingCount; i++) {
    if (rBindings[i].GetType() != PASNObject::Sequence) 
      return TRUE;

    const PASNSequence & rVar = rBindings[i].GetSequence();
    if (rVar.GetSize() != 2 ||
        rVar[0].GetType() != PASNObject::ObjectID) 
      return TRUE;

    varsOut.Append(rVar[0].GetString(), (PASNObject *)rVar[1].Clone());
  }

  return TRUE;
}


// End Of File ///////////////////////////////////////////////////////////////
