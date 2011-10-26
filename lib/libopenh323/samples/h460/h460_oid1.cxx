/* H460_OID1.cxx
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
 * The Original Code is derived from and used in conjunction with the 
 * OpenH323 Project (www.openh323.org/)
 *
 * The Initial Developer of the Original Code is ISVO (Asia) Pte Ltd.
 *
 *
 * Contributor(s): ______________________________________.
 *
 * $Log: h460_oid1.cxx,v $
 * Revision 1.2  2006/05/16 18:49:58  shorne
 * Added more ReleaseComplete notifications
 *
 * Revision 1.1  2006/05/16 16:03:38  shorne
 * Initial commit
 *
 *
 */

#include <ptlib.h>

#include "h460_oid1.h"
#include <h323pdu.h>

#include "testapp/main.h"
//#include "MyH323EndPoint.h"


static const char * baseOID = "1.3.6.1.4.1.17090.0.1";      // Advertised Feature
static const char * typeOID  = "1.3.6.1.4.1.17090.0.1.1";   // Type 1-IM session 
static const char * encOID  = "1.3.6.1.4.1.17090.0.1.3";    // Support Encryption
static const char * OpenOID  = "1.3.6.1.4.1.17090.0.1.4";   // Message Session open/close
static const char * MsgOID  = "1.3.6.1.4.1.17090.0.1.5";    // Message contents

static const char * RegOID  = "1.3.6.1.4.1.17090.0.1.10";
static const char * RegIDOID  = "1.3.6.1.4.1.17090.0.1.10.1";
static const char * RegPwdOID  = "1.3.6.1.4.1.17090.0.1.10.2";

#ifdef _MSC_VER
#pragma warning(disable : 4239)
#endif

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

// Must Declare for Factory Loader.
H460_FEATURE(OID1);

H460_FeatureOID1::H460_FeatureOID1()
: H460_FeatureOID(baseOID)
{
 PTRACE(4,"OID1\tInstance Created");

 remoteSupport = FALSE;
 remoteEnc = FALSE;
 callToken = PString();
 sessionOpen = FALSE;

 EP = NULL;
 CON = NULL;
 FeatureCategory = FeatureSupported;

}

H460_FeatureOID1::~H460_FeatureOID1()
{
}

void H460_FeatureOID1::AttachEndPoint(H323EndPoint * _ep)
{
   EP = (MyH323EndPoint *)_ep; 
}

void H460_FeatureOID1::AttachConnection(H323Connection * _con)
{
   CON = (MyH323Connection *)_con;
   callToken = _con->GetCallToken();
}

BOOL H460_FeatureOID1::OnSendSetup_UUIE(H225_FeatureDescriptor & pdu) 
{

  // Set Call Token
  callToken = CON->GetCallToken();

  // Build Message
  H460_FeatureOID & feat = H460_FeatureOID(baseOID); 

  // Is a IM session call
  if (CON->IMCall) {
      sessionOpen = !CON->IMsession;                // set flag to open session 
      feat.Add(typeOID,H460_FeatureContent(1,8));   // 1 specify Instant Message Call
      CON->DisableH245inSETUP();                    // Turn off H245 in Setup
  }

//  feat.Add(encOID,H460_FeatureContent(true));   // false Support Encryption
  
  // Is Gateway Registration Call
  if ((!CON->IMReg) && (CON->IMRegID.GetLength() > 0)) {
       H460_FeatureTable tab;
       tab.AddParameter(H460_FeatureID(OpalOID(RegIDOID)),H460_FeatureContent(CON->IMRegID));
       tab.AddParameter(H460_FeatureID(OpalOID(RegPwdOID)),H460_FeatureContent(CON->IMRegPwd));
       feat.Add(RegOID,H460_FeatureContent(tab));
  } 


  // Attach PDU
  pdu = feat;

  return TRUE;
}

void H460_FeatureOID1::OnReceiveSetup_UUIE(const H225_FeatureDescriptor & pdu) 
{

   callToken = CON->GetCallToken();

   H460_FeatureOID & feat = (H460_FeatureOID &)pdu;

   if (feat.Contains(OpalOID(typeOID))) {  // This is a Non Call Service
	      CON->DisableH245inSETUP();    // Turn off H245 Tunnelling in Setup

     unsigned calltype = feat.Value(OpalOID(typeOID));
     if (calltype == 1)   // IM Call
         CON->IMCall = TRUE;
	  
   }

//  Remote supports Encryption
//  if (feat.Contains(OpalOID(encOID))) 
//		  remoteEnc = feat.Value(OpalOID(encOID));   

   if (feat.Contains(OpalOID(RegOID)))   // external gateway management
   {

   }

   EP->SupportsIM(callToken);
   remoteSupport = TRUE; 

}

BOOL H460_FeatureOID1::OnSendCallProceeding_UUIE(H225_FeatureDescriptor & pdu) 
{ 
    if (remoteSupport) {
// Build Message
      H460_FeatureOID & feat = H460_FeatureOID(baseOID); 

// Signal to say ready for message
      if (CON->IMCall)
          feat.Add(typeOID,H460_FeatureContent(1,8));   // Notify ready for message

// Responsed Support Encryption
//    if (remoteEnc)
//       feat.Add(encOID,H460_FeatureContent(true));

// Attach PDU
       pdu = feat;
    }

	return remoteSupport; 
}

void H460_FeatureOID1::OnReceiveCallProceeding_UUIE(const H225_FeatureDescriptor & pdu) 
{
 
   remoteSupport = TRUE;
   EP->SupportsIM(callToken);

   H460_FeatureOID & feat = (H460_FeatureOID &)pdu;

//  Remote Supports Encryption
//  if (feat.Contains(OpalOID(encOID)))
//		 remoteEnc = feat.Value(OpalOID(encOID));

//   if Remote Ready for Non-Call 
    if (feat.Contains(OpalOID(typeOID))) { 
       unsigned calltype = feat.Value(OpalOID(typeOID));

//   if IM session send facility msg
       if (calltype == 1) {  
         H323SignalPDU facilityPDU;
         facilityPDU.BuildFacility(*CON, FALSE);
         CON->WriteSignalPDU(facilityPDU);
       }
    } 
}


// Send Message
BOOL H460_FeatureOID1::OnSendFacility_UUIE(H225_FeatureDescriptor & pdu) 
{ 

    if (remoteSupport) {
	// Build Message
      H460_FeatureOID & feat = H460_FeatureOID(baseOID); 
      BOOL contents = FALSE;

       //End Call after receiving message
     if ((sessionOpen != CON->IMsession)) {
          sessionOpen = CON->IMsession;
          feat.Add(OpenOID,H460_FeatureContent(sessionOpen));

       if (sessionOpen)
          EP->IMSessionOpen(callToken);
       else if (!CON->IMCall)
          EP->IMSessionClosed(callToken); 

       contents = TRUE;
     }

	// If Message send as Unicode String
      if (CON->IMmsg.GetLength() > 0) {
         PASN_BMPString str; 
         str.SetValue(CON->IMmsg);
         feat.Add(MsgOID,H460_FeatureContent(str));
         CON->IMmsg = PString();
		 contents = TRUE;
      }

      if (contents) {
         pdu = feat;
         if (CON->IMCall && !sessionOpen)		  
			  EP->IMMessageSent();

         return TRUE;
      }

    }

    return FALSE; 
};

// Receive Message
void H460_FeatureOID1::OnReceiveFacility_UUIE(const H225_FeatureDescriptor & pdu) 
{
   H460_FeatureOID & feat = (H460_FeatureOID &)pdu;
   BOOL open = FALSE;

   if (feat.Contains(OpalOID(OpenOID))) {
	   open = feat.Value(OpalOID(OpenOID));
	   if (open) {
             EP->IMSessionOpen(callToken);
             sessionOpen = TRUE;
             CON->IMsession = TRUE;
             CON->SetCallAnswered();   // Set Flag to specify call is answered 
	   } else {
             if (CON->IMsession)
                 EP->IMSessionClosed(callToken);

             sessionOpen = FALSE;
             CON->IMsession = FALSE;
	   }
   }

   if (feat.Contains(OpalOID(MsgOID))) {
	PASN_BMPString & str = feat.Value(OpalOID(MsgOID));
        EP->ReceivedIM(callToken,str.GetValue());
   }

   if (!CON->IMCall)   // Message in an existing connection
	   return;

   if (sessionOpen) {
       H323SignalPDU connectPDU;
       connectPDU.BuildConnect(*CON);
       CON->WriteSignalPDU(connectPDU); // Send H323 Connect PDU
   } else 
       CON->ClearCall();    // Send Release Complete

};

// You end connection
BOOL H460_FeatureOID1::OnSendReleaseComplete_UUIE(H225_FeatureDescriptor & pdu) 
{ 
	if (sessionOpen) {
       EP->IMSessionClosed(callToken);
	   sessionOpen = FALSE;

	// Build Message
      H460_FeatureOID & feat = H460_FeatureOID(baseOID); 
      feat.Add(OpenOID,H460_FeatureContent(sessionOpen));
      pdu = feat;
      return TRUE;
	}

   return FALSE; 
};

// Other person ends connection
void H460_FeatureOID1::OnReceiveReleaseComplete_UUIE(const H225_FeatureDescriptor & pdu) 
{
   H460_FeatureOID & feat = (H460_FeatureOID &)pdu;

    if (sessionOpen && feat.Contains(OpalOID(OpenOID))) {
	   BOOL open = feat.Value(OpalOID(OpenOID));
		if (!open) {
          sessionOpen = FALSE;
          EP->IMSessionClosed(callToken);
		}
	}
};  

#ifdef _MSC_VER
#pragma warning(default : 4239)
#endif