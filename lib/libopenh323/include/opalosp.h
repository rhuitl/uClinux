/*
 * opalosp.h
 *
 * OSP protocol handler
 *
 * OpenH323 Library
 *
 * Copyright (C) 2004 Post Increment
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
 * The Original Code is Open H323 Library.
 *
 * The Initial Developer of the Original Code is Post Increment
 *
 * This code was written with assistance from TransNexus, Inc.
 * http://www.transnexus.com
 *
 * Contributor(s): ______________________________________.
 *
 * $Log: opalosp.h,v $
 * Revision 1.16  2005/12/20 02:08:02  csoutheren
 * Look for called and calling number information in Q.931 header for OSP validation
 *
 * Revision 1.15  2005/12/02 00:07:12  csoutheren
 * Look for calling number information in Q.931 header
 *
 * Revision 1.14  2005/11/30 13:05:01  csoutheren
 * Changed tags for Doxygen
 *
 * Revision 1.13  2005/10/13 12:34:47  csoutheren
 * Removed redundant inline statement
 *
 * Revision 1.12  2005/09/16 08:08:36  csoutheren
 * Split ReportUsage from CallEnd function
 *
 * Revision 1.11  2005/08/30 08:30:14  csoutheren
 * Added support for setting connection count on OSP server
 *
 * Revision 1.10  2005/08/27 02:11:58  csoutheren
 * Added support for different pthread library required by new OSP toolkit on Windows
 * Added support for new parameters to GetFirst and GetNext
 * Fixed incorrect usage of destination address and destination device
 *
 * Revision 1.9  2005/08/15 01:58:13  csoutheren
 * Adde support for version 3.3.2 of the OSP Toolkit
 *
 * Revision 1.8  2005/07/25 01:23:28  csoutheren
 * Added ability to select token algorithm when validating OSP tokens
 *
 * Revision 1.7  2005/01/03 06:25:52  csoutheren
 * Added extensive support for disabling code modules at compile time
 *
 * Revision 1.6  2004/12/20 02:32:34  csoutheren
 * Cleeaned up OSP functions
 *
 * Revision 1.5  2004/12/16 00:34:35  csoutheren
 * Fixed reporting of call end time and code
 * Added GetNextDestination
 *
 * Revision 1.4  2004/12/14 06:22:21  csoutheren
 * More OSP implementation
 *
 * Revision 1.3  2004/12/09 23:38:34  csoutheren
 * More OSP implementation
 *
 * Revision 1.2  2004/12/08 05:16:13  csoutheren
 * Fixed OSP compilation on Linux
 *
 * Revision 1.1  2004/12/08 01:59:23  csoutheren
 * initial support for Transnexus OSP toolkit
 *
 */

#ifndef __OSP_H
#define __OSP_H

#ifdef P_USE_PRAGMA
#pragma interface
#endif

#include "openh323buildopts.h"
#include <guid.h>
#include <ptclib/pssl.h>

#include "transports.h"
#include "h225.h"

class H225_AliasAddress;
class H323SignalPDU;
class H225_Setup_UUIE;
class H225_AdmissionRequest;
class H323Connection;

#ifdef H323_TRANSNEXUS_OSP

/**
  * This file implements a simple interface to the Transnexus OSP Toolkit. 
  */

// include the Transnexus headers
#include <osp/osp.h>

namespace OpalOSP {

#define DECLARE_GET_SET(var, suffix, type) \
  public: \
    void Set##suffix(type v)  { var = v; } \
    type Get##suffix() const  { return var; } \
  protected: \
    type var; \

///////////////////////////////////////////////////////////////////////////////
//
//  Global functions (inside the OpalOSP namespace)
//

/** Initialise or uninitialise the OSP toolkit. This function is idempotent
  * 
  */
void Initialise(BOOL uninitialise = FALSE);

/** Format various datatypes as required by the OSP toolkit
  */
PString AddressToOSPString(
  const PString & taddr  ///<  hostname or dotted quad
);
H323TransportAddress OSPStringToAddress(
  const PString & str, WORD defaultPort
);
PString TransportAddressToOSPString(
  const H323TransportAddress & taddr  ///<  H323 transport address
);
inline PString TransportAddressToOSPString(
  const H225_TransportAddress & taddr  ///<  H323 transport address
)
{ return TransportAddressToOSPString(H323TransportAddress(taddr)); }

/** Decompose a H.225 Alias Address into the parts needed for the OSP toolkit
  */
BOOL ConvertAliasToOSPString(
    const H225_AliasAddress & alias,   ///<  alias address to decompose
    int & format,                      ///<  enum format type (see OSPE_NUMBERING_FORMAT)
    PString & str                      ///<  string component
);

inline PString IpAddressToOSPString(
  const PIPSocket::Address & addr
)
{
  return psprintf("[%d.%d.%d.%d]", addr.Byte1(), addr.Byte2(), addr.Byte3(), addr.Byte4());
}

inline PString IpAddressPortToOSPString(
  const PIPSocket::Address & addr, ///<  IP address of OSP service provider
  WORD port                        ///<  port of OSP service provider);
)
{
  return psprintf("[%d.%d.%d.%d]:%d", addr.Byte1(), addr.Byte2(), addr.Byte3(), addr.Byte4(), port);
}

//////////////////////////////////////////////////////////////////////////////

/**
  * This class abstracts the concept of an OSP service provider
  */

class Provider : public PObject
{
  PCLASSINFO(Provider, PObject);
  public:
    enum {
      IllegalHandle = -1
    };

    /** Create an empty OSP provider object
      */
    Provider();

    /** Destroy an OSP provider object. 
      * This will call Close if the provider was opened
      */
    ~Provider();

    /**  Open an OSP provider object given a hostname.
      *  The SSL keys required for the connections are assumed to be in the following filenames:
      *      hostname_priv.pem    private key 
      *      hostname_cert.pem    public key (as cert)
      *      hostname_cacert.pem  CA cert 
      */
    inline int Open(
      const PString & servicePoint              ///<  URL of OSP service provider
    )
    { return Open(servicePoint, PDirectory()); }
    int Open(
      const PString & servicePoint,             ///<  URL of OSP service provider
      const PDirectory & certDir                ///<  Directory containing certificates
    );
    /** Open an OSP provider object given key filenames
      */
    int Open(
      const PString & servicePoint,             ///<  URL of OSP service provider
      const PFilePath & localPrivateKeyName,    ///<  filename of file with local private key 
      const PFilePath & localPublicCertName,    ///<  filename of file with local public key (as cert)
      const PFilePath & localAuthCertName       ///<  filename of file with OSP CA cert 
    );

    /** Open an OSP provider object given key objects
      */
    int Open(
        const PString & servicePoint,         ///<  URL or IP address of OSP 
       PSSLPrivateKey & localPrivateKey,      ///<  local private key
      PSSLCertificate & localPublicCert,      ///<  local public key (as cert)
      PSSLCertificate & localAuthCert         ///<  OSP CA cert
    );

    /** Close connection to an OSP service provider
    */
    int Close();

    /** This operator allows a OpalOSP::Provider object to be used as a 
      * replacement for a OSPTPROVHANDLE
      */
    inline operator ::OSPTPROVHANDLE ()
    { return handle; }

    /** return TRUE if the provider handler is open
    */
    inline BOOL IsOpen() const
    { return handle != IllegalHandle; }

    inline PIPSocket::Address GetHostAddress() const
    { return hostAddress; }

    /** Declare variables and GetX/SetX operators for various OSP provider parameters.
      * These can be set before the Open call to change the default values used 
      * when the OSP provider is opened
      */
    DECLARE_GET_SET(deleteTimeout,  DeleteTimeout,  int);
    DECLARE_GET_SET(maxSimultConn,  MaxSimultConn,  int);
    DECLARE_GET_SET(httpPersist,    HttpPersist,    int);
    DECLARE_GET_SET(httpRetryDelay, HttpRetryDelay, int);
    DECLARE_GET_SET(httpRetry,      HttpRetry,      int);      
    DECLARE_GET_SET(httpTimeout,    HttpTimeout,    int);
    DECLARE_GET_SET(sslLifeTime,    SSLLifetime,    int);
    DECLARE_GET_SET(deviceID,       DeviceID,       PString);
    DECLARE_GET_SET(customerID,     CustomerID,     PString);
    DECLARE_GET_SET(messageCount,   MessageCount,   int);

  protected:
    ::OSPTPROVHANDLE handle;
    PIPSocket::Address hostAddress;
};

//////////////////////////////////////////////////////////////////////////////

/**
  * This class abstracts the concept of an OSP transaction
  */

class Transaction : public PObject
{
  PCLASSINFO(Transaction, PObject);
  public:
    enum {
      IllegalHandle = -1
    };

    /** Create an empty OSP transaction
      */
    Transaction();

    /** Destroy an OSP transaction
      * This will call Close of the transaction was opened
      */
    ~Transaction();

    /** Open a new transaction
      */
    int Open(Provider & _provider)
    { return Open(_provider, ""); }

    int Open(
      Provider & _provider,     ///<  provider to use
      const PString & user      ///<  user identifier
    );

    /** this structure contains the information required
      * to authorise a call
      */
    struct AuthorisationInfo {

      /** extract authorisation information from a SETUP PDU
       */
      BOOL Extract(
        const H323SignalPDU & setupPDU
      );

      /** extract authorisation information from an ARQ PDU
       */
      BOOL Extract(
        const H225_AdmissionRequest & arqPDU
      );

      PString ospvSource;
      PString ospvSourceDevice;
      H225_AliasAddress callingNumber;
      H225_AliasAddress calledNumber;
      PBYTEArray callID;
    };
    /** Authorise an outgoing call
      */
    int Authorise(
      AuthorisationInfo & info,
      unsigned & numberOfDestinations
    );
    int Authorise(
      const PString & ospvSource,
      const PString & ospvSourceDevice,
      const H225_AliasAddress & callingNumber,
      const H225_AliasAddress & calledNumber,
      const PBYTEArray & callID,
      unsigned & numberOfDestinations
    );
    int Authorise(
      const PString & ospvSource,
      const PString & ospvSourceDevice,
      const PString & ospvCallingNumber,
      int ospvCallingNumberFormat,
      const PString & ospvCalledNumber,
      int ospvCalledNumberFormat,
      const PBYTEArray & callID,
      unsigned & numberOfDestinations
    );

    /**
      */
    struct DestinationInfo {

      /** insert destination information into a SETUP PDU
       */
      BOOL Insert(
        H323SignalPDU & setupPDU,
        BOOL useCiscoBug = FALSE
      );
      BOOL Insert(
        H225_Setup_UUIE & setupPDU,
        BOOL useCiscoBug = FALSE
      );

      /** insert destination information into a AdmissionConfirm PDU
       */
      BOOL Insert(
        H225_AdmissionConfirm & acf,
        BOOL useCiscoBug = FALSE
      );

      void InsertToken(H225_ArrayOf_ClearToken & clearTokens, BOOL useCiscoBug = FALSE);

      unsigned timeLimit;
      PBYTEArray callID;
      H225_AliasAddress calledNumber;
      BOOL hasCallingNumber;
      H225_AliasAddress callingNumber;
      H323TransportAddress destinationAddress;
      PString destination;
      PBYTEArray token;
    };

    /**  Get the first destination for a transaction
      */
    int GetFirstDestination(
      DestinationInfo & info
    );
    inline int GetFirstDestination(
      unsigned & timeLimit,
      PBYTEArray & callID,
      PString & calledNumber,
      PString & destination,
      PString & device,
      PBYTEArray & token
    )
    { PString callingNumber; return GetFirstDestination(timeLimit, callID, calledNumber, callingNumber, destination, device, token); }
    int GetFirstDestination(
      unsigned & timeLimit,
      PBYTEArray & callID,
      PString & calledNumber,
      PString & callingNumber,
      PString & destination,
      PString & device,
      PBYTEArray & token
    );

    /**  Get the next destination for a transaction
      */
    int GetNextDestination(
      int endReason,
      DestinationInfo & info
    );
    inline int GetNextDestination(
      int endReason,
      unsigned & timeLimit,
      PBYTEArray & callID,
      PString & calledNumber,
      PString & destination,
      PString & device,
      PBYTEArray & token
    )
    { PString callingNumber; return GetNextDestination(endReason, timeLimit, callID, calledNumber, callingNumber, destination, device, token); }
    int GetNextDestination(
      int endReason,
      unsigned & timeLimit,
      PBYTEArray & callID,
      PString & calledNumber,
      PString & callingNumber,
      PString & destination,
      PString & device,
      PBYTEArray & token
    );

    /** Set call statistics
      */
    void CallStatistics(
      unsigned lostSentPackets,
      signed lostFractionSent,
      unsigned lostReceivedPackets,
      signed lostFractionReceived,
      const PTime & firstRTPTime
    );

    /** End the call
      */
    void CallEnd(
      H323Connection & conn
    );

    /**
      * Report usage
      */
    void ReportUsage(
      H323Connection & conn
    );

    /** Validate an incoming call
      */
    struct ValidationInfo {

      ValidationInfo()
      { tokenAlgo = TOKEN_ALGO_SIGNED; }

      /** extract validation information from a SETUP PDU
       */
      BOOL Extract(
        const H323SignalPDU & setupPDU
      );

      /** extract validation information from an ARQ PDU
       */
      BOOL Extract(
        const H225_AdmissionRequest & arqPDU
      );

      BOOL ExtractToken(
        const H225_ArrayOf_ClearToken & clearTokens
      );

      PString ospvSource;
      PString ospvDest;
      PString ospvSourceDevice;
      PString ospvDestDevice;
      H225_AliasAddress callingNumber;
      H225_AliasAddress calledNumber;
      PBYTEArray callID;
      PBYTEArray token;
      unsigned tokenAlgo;
    };
    int Validate(
      const ValidationInfo & info,
      BOOL & authorised,
      unsigned & timeLimit
    );
    // backward compatible API
    int Validate(
      const PString & ospvSource,
      const PString & ospvDest,
      const PString & ospvSourceDevice,
      const PString & ospvDestDevice,
      const H225_AliasAddress & callingNumber,
      const H225_AliasAddress & calledNumber,
      const PBYTEArray & callID,
      const PBYTEArray & token,
      BOOL & authorised,
      unsigned & timeLimit
    )
    { return Validate(ospvSource, ospvDest, ospvSourceDevice, ospvDestDevice, 
                      callingNumber, calledNumber, 
                      callID, token, TOKEN_ALGO_SIGNED, authorised, timeLimit); 
    }

    // backward compatible API
    int Validate(
      const PString & ospvSource,
      const PString & ospvDest,
      const PString & ospvSourceDevice,
      const PString & ospvDestDevice,
      int ospvCallingNumberFormat,
      const PString & ospvCallingNumber,
      int ospvCalledNumberFormat,
      const PString & ospvCalledNumber,
      const PBYTEArray & callID,
      const PBYTEArray & token,
      BOOL & authorised,
      unsigned & timeLimit
    )
    { return Validate(ospvSource, ospvDest, ospvSourceDevice, ospvDestDevice, 
                      ospvCallingNumberFormat, ospvCallingNumber, 
                      ospvCalledNumberFormat,  ospvCalledNumber,
                      callID, token, TOKEN_ALGO_SIGNED, authorised, timeLimit); 
    }

    int Validate(
      const PString & ospvSource,
      const PString & ospvDest,
      const PString & ospvSourceDevice,
      const PString & ospvDestDevice,
      const H225_AliasAddress & callingNumber,
      const H225_AliasAddress & calledNumber,
      const PBYTEArray & callID,
      const PBYTEArray & token,
      unsigned int tokenAlgo,
      BOOL & authorised,
      unsigned & timeLimit
    );
    int Validate(
      const PString & ospvSource,
      const PString & ospvDest,
      const PString & ospvSourceDevice,
      const PString & ospvDestDevice,
      int ospvCallingNumberFormat,
      const PString & ospvCallingNumber,
      int ospvCalledNumberFormat,
      const PString & ospvCalledNumber,
      const PBYTEArray & callID,
      const PBYTEArray & token,
      unsigned int tokenAlgo,
      BOOL & authorised,
      unsigned & timeLimit
    );

    /** Close a transaction
      */
    int Close();

    /** return TRUE if the provider handler is open
    */
    inline BOOL IsOpen() const
    { return handle != IllegalHandle; }

    BOOL CheckOpenedAndNotEnded(const char * str);

    inline operator ::OSPTTRANHANDLE ()
    { return handle; }

    Provider * GetProvider() const
    { return provider; }

  protected:
    Provider * provider;
    PString user;
    ::OSPTTRANHANDLE handle;

    BOOL ended;

    unsigned lostSentPackets;
    unsigned lostReceivedPackets;
    signed lostFractionSent;
    signed lostFractionReceived;
    PTime firstRTPTime;
};

} // namespace OpalOSP 

#endif // H323_TRANSNEXUS_OSP

#endif
