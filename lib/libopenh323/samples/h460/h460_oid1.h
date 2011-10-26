/* H460_OID1.h
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
 * $Log: h460_oid1.h,v $
 * Revision 1.1  2006/05/16 16:03:38  shorne
 * Initial commit
 *
 *
 *
 */

#ifndef H_H460_FeatureOID1
#define H_H460_FeatureOID1

#include <h4601.h>

// Must call the following
#define P_FORCE_STATIC_PLUGIN
#include <ptlib/plugin.h>

#if _MSC_VER
#pragma once
#endif 

class MyH323EndPoint;
class MyH323Connection;
class H460_FeatureOID1 : public H460_FeatureOID 
{
    PCLASSINFO(H460_FeatureOID1,H460_FeatureOID);

public:

    H460_FeatureOID1();
    virtual ~H460_FeatureOID1();

    // Universal Declarations Every H460 Feature should have the following
    virtual void AttachEndPoint(H323EndPoint * _ep);
    virtual void AttachConnection(H323Connection * _con);

    static PStringList GetFeatureName() { return PStringList("H460_FeatureOID1"); };
    static PStringList GetFeatureFriendlyName() { return PStringList("Non Call Related Services"); };
    static int GetPurpose()	{ return FeatureSignal; };

    // H.323 Message Manuipulation
        // Advertise the Feature
    virtual BOOL OnSendSetup_UUIE(H225_FeatureDescriptor & pdu);
    virtual void OnReceiveSetup_UUIE(const H225_FeatureDescriptor & pdu);

    virtual BOOL OnSendCallProceeding_UUIE(H225_FeatureDescriptor & pdu);
    virtual void OnReceiveCallProceeding_UUIE(const H225_FeatureDescriptor & pdu);

	// Send/Recieve Message
    virtual BOOL OnSendFacility_UUIE(H225_FeatureDescriptor & pdu);
    virtual void OnReceiveFacility_UUIE(const H225_FeatureDescriptor & pdu);

	// Release Complete
    virtual BOOL OnSendReleaseComplete_UUIE(H225_FeatureDescriptor & pdu);
    virtual void OnReceiveReleaseComplete_UUIE(const H225_FeatureDescriptor & pdu);  
	

private:
	PString callToken;      // Call
	BOOL remoteSupport;
	BOOL remoteEnc;
	BOOL sessionOpen;

	MyH323EndPoint * EP;
	MyH323Connection * CON;

};

// Need to declare for Factory Loader
PWLIB_STATIC_LOAD_PLUGIN(H460_FeatureOID1, H460_Feature);

#endif
