/*
 * opalosp.cxx
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
 * $Log: opalosp.cxx,v $
 * Revision 1.24  2006/06/09 07:15:34  csoutheren
 * Fixed warning when using old OSP toolkit
 *
 * Revision 1.23  2006/03/26 23:49:20  csoutheren
 * Added extra logging for OSP release codes
 *
 * Revision 1.22  2006/03/09 23:43:23  csoutheren
 * Change OSP call duration
 *
 * Revision 1.21  2006/02/27 07:04:18  csoutheren
 * Ensure call ID allocated by the OSP toolkit is freed by the toolkit
 *
 * Revision 1.20  2006/02/24 04:53:01  csoutheren
 * Fixed problem with incorrect flag in OSP population
 *
 * Revision 1.19  2006/02/21 23:50:21  csoutheren
 * Remove requirement for destination call signaling address in SETUP for OSP validation
 *
 * Revision 1.18  2006/02/09 03:17:01  csoutheren
 * Use OSP toolkit routines for allocating call IDs rather than automatic variables
 *
 * Revision 1.17  2006/01/30 06:11:04  csoutheren
 * Added extra logging for OSP report usage call
 *
 * Revision 1.16  2005/12/20 02:08:02  csoutheren
 * Look for called and calling number information in Q.931 header for OSP validation
 *
 * Revision 1.15  2005/12/08 06:31:13  csoutheren
 * Look for called number information in Q.931 header
 *
 * Revision 1.14  2005/12/02 00:07:12  csoutheren
 * Look for calling number information in Q.931 header
 *
 * Revision 1.13  2005/09/16 08:08:36  csoutheren
 * Split ReportUsage from CallEnd function
 *
 * Revision 1.12  2005/08/30 08:30:14  csoutheren
 * Added support for setting connection count on OSP server
 *
 * Revision 1.11  2005/08/30 01:12:38  csoutheren
 * Added automatic detection of OSP toolkit version on Unix
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
 * Revision 1.7  2005/01/03 14:03:42  csoutheren
 * Added new configure options and ability to disable/enable modules
 *
 * Revision 1.6  2004/12/20 02:32:36  csoutheren
 * Cleeaned up OSP functions
 *
 * Revision 1.5  2004/12/16 00:34:36  csoutheren
 * Fixed reporting of call end time and code
 * Added GetNextDestination
 *
 * Revision 1.4  2004/12/14 06:22:22  csoutheren
 * More OSP implementation
 *
 * Revision 1.3  2004/12/09 23:38:41  csoutheren
 * More OSP implementation
 *
 * Revision 1.2  2004/12/08 05:16:14  csoutheren
 * Fixed OSP compilation on Linux
 *
 * Revision 1.1  2004/12/08 01:59:23  csoutheren
 * initial support for Transnexus OSP toolkit
 *
 */

#ifdef __GNUC__
#pragma implementation "opalosp.h"
#endif

#include <ptlib.h>
#include <ptlib/sockets.h>
#include <ptclib/url.h>

#include <h323.h>
#include "opalosp.h"
#include <h225.h>
#include <h323pdu.h>
#include <h323ep.h>

#ifdef H323_TRANSNEXUS_OSP

//
// Windows has no way to determine which version of the OSP API is being used,
// while Unix systems will use a configure test.
// On Windows, set the default to the most recent version. This will need manual
//  configuration if older versions of the toolkit are used
//
#ifdef _MSC_VER
#define H323_NEW_OSP_API     1  

#pragma comment(lib, H323_TRANSNEXUS_OSP_DIR_LIBRARY1)

#ifdef H323_NEW_OSP_API
#pragma comment(lib, H323_TRANSNEXUS_OSP_DIR_LIBRARY2b)
#else
#pragma comment(lib, H323_TRANSNEXUS_OSP_DIR_LIBRARY2a)
#endif
#endif

#define DEFAULT_SSL_LIFETIME      3600        // SSL lifetime
#define DEFAULT_MAX_SIMULT_CONN   32          // maximum simultaneous connections
#define DEFAULT_HTTP_PERSIST      60          // HTTP persistence of 1 minute
#define DEFAULT_HTTP_RETRY_DELAY  600         // HTTP retry delay of 10 minutes
#define DEFAULT_HTTP_RETRY        3           // HTTP retry count of 3
#define DEFAULT_HTTP_TIMEOUT      10000       // HTTP timeout of 10 secs
#define DEFAULT_DELETE_TIMEOUT    4           // delete timeout

#define CALLID_SIZE               20          // size of call ID
#define CALLED_NUMBER_SIZE        100         // size of storage for called number
#define CALLING_NUMBER_SIZE       100         // size of storage for calling number
#define DESTINATION_SIZE          100         // size of storage for destination
#define DEVICE_SIZE               100         // size of storage for device
#define TOKEN_SIZE                16384       // size of OSP token

////////////////////////////////////////////////////////////////////////////////////////////////////////

class OSPShutDown : public PProcessStartup
{
  PCLASSINFO(OSPShutDown, PProcessStartup);
  public:
    void OnShutdown()
    { OpalOSP::Initialise(FALSE); }
};

PFactory<PProcessStartup>::Worker<OSPShutDown> ospPluginLoaderStartupFactory("OSPShutDown", true);

void OpalOSP::Initialise(BOOL shutdown)
{
  static BOOL initialised = FALSE;

  if (!initialised && !shutdown) {
    ::OSPPInit(FALSE);
    initialised = TRUE;
  }
  else if (initialised && shutdown) {
    ::OSPPCleanup();
  }
}

PString OpalOSP::TransportAddressToOSPString(const H323TransportAddress & taddr)
{
  PIPSocket::Address addr;
  WORD port;
  taddr.GetIpAndPort(addr, port);
  return IpAddressPortToOSPString(addr, port);
}

PString OpalOSP::AddressToOSPString(const PString & str)
{
  int b1, b2, b3, b4, port;
  if (sscanf((const char *)str, "%d.%d.%d.%d:%d", &b1, &b2, &b3, &b4, &port) == 5)
    return psprintf("[%d.%d.%d.%d]:%d", b1, b2, b3, b4, port);
  else if (sscanf((const char *)str, "%d.%d.%d.%d", &b1, &b2, &b3, &b4) == 4)
    return psprintf("[%d.%d.%d.%d]", b1, b2, b3, b4);
  else
    return str;
}

H323TransportAddress OpalOSP::OSPStringToAddress(const PString & str, WORD defaultPort)
{
  int b1, b2, b3, b4, port;
  if (sscanf((const char *)str, "[%d.%d.%d.%d]:%d", &b1, &b2, &b3, &b4, &port) == 5)
    return H323TransportAddress(PIPSocket::Address((BYTE)b1, (BYTE)b2, (BYTE)b3, (BYTE)b4), (WORD)port);
  else if (sscanf((const char *)str, "[%d.%d.%d.%d]", &b1, &b2, &b3, &b4) == 4)
    return H323TransportAddress(PIPSocket::Address((BYTE)b1, (BYTE)b2, (BYTE)b3, (BYTE)b4), defaultPort);
  else
    return H323TransportAddress(str);;
}

BOOL OpalOSP::ConvertAliasToOSPString(const H225_AliasAddress & alias, int & format, PString & str)
{
  str = H323GetAliasAddressString(alias);
  switch (alias.GetTag()) {
    case H225_AliasAddress::e_dialedDigits:
      format = ::OSPC_E164;
      return TRUE;
      break;

    case H225_AliasAddress::e_url_ID:
      format = ::OSPC_URL;
      return TRUE;
      break;

    case H225_AliasAddress::e_email_ID:
    case H225_AliasAddress::e_h323_ID:
    case H225_AliasAddress::e_transportID:
    case H225_AliasAddress::e_partyNumber:
    case H225_AliasAddress::e_mobileUIM:
      break;
  }
  return FALSE;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////
//
//  provider functions
//

OpalOSP::Provider::Provider()
{ 
  Initialise();

  handle = IllegalHandle; 

  sslLifeTime    = DEFAULT_SSL_LIFETIME;
  maxSimultConn  = DEFAULT_MAX_SIMULT_CONN;
  httpPersist    = DEFAULT_HTTP_PERSIST;
  httpRetryDelay = DEFAULT_HTTP_RETRY_DELAY;
  httpRetry      = DEFAULT_HTTP_RETRY;
  httpTimeout    = DEFAULT_HTTP_TIMEOUT;
  deleteTimeout  = DEFAULT_DELETE_TIMEOUT;
  messageCount   = 0;
}

OpalOSP::Provider::~Provider()
{
  Close();
}

int OpalOSP::Provider::Open(const PString & servicePoint, const PDirectory & certDir)
{
  PURL url(servicePoint, "http");
  PString hostName = url.GetHostName();
  if (!PIPSocket::GetHostAddress(hostName, hostAddress)) {
    PTRACE(2, "OSP\tCannot resolve address of OSP server " << hostName);
    return -1; 
  }

  PFilePath privateKeyFilename = certDir + (hostName + "_priv.pem");
  PFilePath publicKeyFilename  = certDir + (hostName + "_cert.pem");
  PFilePath serverCAFilename   = certDir + (hostName + "_cacert.pem");

  return Open(servicePoint, privateKeyFilename, publicKeyFilename, serverCAFilename);
}

int OpalOSP::Provider::Open(const PString & servicePoint,
                          const PFilePath & localPrivateKeyName,
                          const PFilePath & localPublicCertName,
                          const PFilePath & localAuthCertName)
{
  PSSLPrivateKey privateKey;
  if (!privateKey.Load(localPrivateKeyName)) {
    PTRACE(2, "OSP\tCannot load public cert " << localPrivateKeyName);
    return -1;
  }

  PSSLCertificate publicCert;
  if (!publicCert.Load(localPublicCertName)) {
    PTRACE(2, "OSP\tCannot load public cert " << localPublicCertName);
    return -1;
  }

  PSSLCertificate authCert;
  if (!authCert.Load(localAuthCertName)) {
    PTRACE(2, "OSP\tCannot load auth cert " << localAuthCertName);
    return -1;
  }

  return Open(servicePoint, privateKey, publicCert, authCert);
}

int OpalOSP::Provider::Open(const PString & servicePoint,
                           PSSLPrivateKey & localPrivateKey,
                          PSSLCertificate & localPublicCert,
                          PSSLCertificate & localAuthCert)
{
  const char * ospvServicePoint = (const char *)servicePoint;

  OSPTPRIVATEKEY localKey;
  PBYTEArray localKeyData   = localPrivateKey.GetData();
  localKey.PrivateKeyData   = localKeyData.GetPointer();
  localKey.PrivateKeyLength = localKeyData.GetSize();

  OSPTCERT localCert;
  PBYTEArray localCertData  = localPublicCert.GetData();
  localCert.CertData        = localCertData.GetPointer();
  localCert.CertDataLength  = localCertData.GetSize();

  OSPTCERT authCert;
  PBYTEArray authCertData   = localAuthCert.GetData();
  authCert.CertData         = authCertData.GetPointer();
  authCert.CertDataLength   = authCertData.GetSize();
  const OSPTCERT * authCerts = &authCert;

  unsigned long * ospvMessageCount = NULL;
  if (messageCount > 0) {
    ospvMessageCount = new unsigned long[1];
    *ospvMessageCount = messageCount;
  }

  // create the provider handle
  int stat = ::OSPPProviderNew(
                    1,                              // number of service points
                    &ospvServicePoint,              // service point data
                    ospvMessageCount,               // max mesages per service point
                    "",                             // audit URL
                    &localKey,                      // private key
                    &localCert,                     // public cert
                    1,                              // number of public certs
                    &authCerts,                     // public cert
                    0,                              // use local validation
                    sslLifeTime,                    // SSL lifetime of one hour
                    maxSimultConn,                  // maximum simultaneous connections
                    httpPersist,                    // HTTP persistence of 1 minute
                    httpRetryDelay,                 // HTTP retry delay of 10 minutes
                    httpRetry,                      // HTTP retry count of 3
                    httpTimeout,                    // HTTP timeout of 3.5 secs
                    (const char *)customerID,       // customer ID
                    (const char *)deviceID,         // device ID
                    &handle);

  delete[](ospvMessageCount);

  PTRACE_IF(1, stat != 0, "OSP\tOSPPProviderNew returned status " << stat);

  if (stat != 0)
    handle = IllegalHandle;
  else
    PTRACE(2, "OSP\tOSPPProviderNew succeeded ");

  return stat;
}

int OpalOSP::Provider::Close()
{
  int stat = 0;

  if (IsOpen()) {
    stat = ::OSPPProviderDelete(handle, deleteTimeout);
    PTRACE(2, "OSP\tOSPPProviderDelete returned status " << stat);
    handle = IllegalHandle;
  }

  return stat;
}


////////////////////////////////////////////////////////////////////////////////////////////////////////
//
//  transaction functions
//

OpalOSP::Transaction::Transaction()
  : provider(NULL)
{ 
  handle = IllegalHandle;
//  endReason = H323Connection::NumCallEndReasons;
}

OpalOSP::Transaction::~Transaction()
{ 
  Close();
}

BOOL OpalOSP::Transaction::CheckOpenedAndNotEnded(const char * str)
{
  if (!IsOpen()) {
    PTRACE(1, "OSP\tAttempt to " << str << " unopened transaction");
    return FALSE;
  }
  if (ended) {
    PTRACE(1, "OSP\tAttempt to " << str << " ended transaction");
    return FALSE;
  }
  return TRUE;
}


int OpalOSP::Transaction::Open(Provider & _provider, const PString & _user)
{ 
  // make sure the transaction is not already open
  if (IsOpen()) {
    PTRACE(1, "OSP\tAttempt to open transaction that is already open");
    return -1;
  }

  // make sure the provider is open
  if (!_provider.IsOpen())
    return -1;
  provider = &_provider;

  // reset the call information
  user      = _user;
  ended     = FALSE;
  lostSentPackets  = lostReceivedPackets  = 0;
  lostFractionSent = lostFractionReceived = -1;

  // create the transaction
  int stat = ::OSPPTransactionNew(*provider, &handle);  

  if (stat != 0) {
    handle = IllegalHandle;
  }

  return stat;
}

void OpalOSP::Transaction::CallStatistics(unsigned _lostSentPackets,
                                          signed   _lostFractionSent,
                                          unsigned _lostReceivedPackets,
                                          signed   _lostFractionReceived,
                                      const PTime & _firstRTPTime)
{
  if (CheckOpenedAndNotEnded("set call statistics")) {
    lostSentPackets      = _lostSentPackets;
    lostFractionSent     = _lostFractionSent;
    lostReceivedPackets  = _lostReceivedPackets;
    lostFractionReceived = _lostFractionReceived;
    firstRTPTime         = _firstRTPTime;
  }
}

static OSPTTIME ValidateOSPTime(const PTime & time)
{
  if (time.IsValid())
    return (OSPTTIME)time.GetTimeInSeconds();

  return 0;
}

void OpalOSP::Transaction::CallEnd(H323Connection & conn)
{
  if (!CheckOpenedAndNotEnded("end"))
    return;

  int result;

  // convert end reason to the correct code
  // note that OSP codes are Q.931 codes, except for the UnknownCauseIE and normal call clearing
  H323Connection::CallEndReason endReason= conn.GetCallEndReason();
  if (endReason != H323Connection::NumCallEndReasons) {
    H225_ReleaseCompleteReason h225Reason;
    int ospReason = (int)H323TranslateFromCallEndReason((H323Connection::CallEndReason)endReason, h225Reason); 
    if (ospReason == Q931::NormalCallClearing)
      ospReason = OSPC_FAIL_NORMAL_CALL_CLEARING;
    else if (ospReason == Q931::UnknownCauseIE)
      ospReason = OSPC_FAIL_GENERAL;
    if (ospReason != OSPC_FAIL_NORMAL_CALL_CLEARING) {
      PTRACE(4, "OSP\tH323 call end reason " << endReason << " converted to OSP/Q.931 release code " << ospReason);
      result = ::OSPPTransactionRecordFailure(*this, (OSPEFAILREASON)ospReason);
      PTRACE_IF(1, result != 0, "OSP\tSetting result code failed");
    }
  }

  ReportUsage(conn);
}

void OpalOSP::Transaction::ReportUsage(H323Connection & conn)
{
  if (!CheckOpenedAndNotEnded("end")) {
    PTRACE(4, "OSP\tReportUsage skipped as transaction not opened or already reported");
    return;
  }

  // calculate duration of the call, in seconds
  unsigned ospvCallDuration = 0;
  if (conn.GetConnectionStartTime().IsValid())
    ospvCallDuration = ((unsigned)(PTime() - conn.GetConnectionStartTime()).GetMilliSeconds() + 500) / 1000 ;

#ifdef H323_NEW_OSP_API

  // get start time of call, in 1970 epoch
  OSPTTIME ospvStartTime = ValidateOSPTime(conn.GetSetupUpTime());

  // get end time of call, in 1970 epoch
  OSPTTIME ospvEndTime = ValidateOSPTime(conn.GetConnectionEndTime());

  // get alerting time of call, in 1970 epoch
  OSPTTIME ospvAlertTime = ValidateOSPTime(conn.GetAlertingTime());

  // get flag indicating whether local endpoint released the call
  BOOL localRelease = conn.GetReleaseSequence() == H323Connection::ReleaseSequence_Local;

  // get flag for whether originator released the call
  int ospvReleaseSource = (conn.HadAnsweredCall() ? !localRelease : localRelease) ? 0 : 1;

#endif

  // get connection time of call, in 1970 epoch
  OSPTTIME ospvConnectionTime = ValidateOSPTime(conn.GetConnectionStartTime());

  // get post dial delay time (time from SETUP to media)
#ifdef H323_NEW_OSP_API
  unsigned ospvPostDialDelay = conn.GetReverseMediaOpenTime().IsValid() ? (((unsigned)(conn.GetReverseMediaOpenTime() - conn.GetSetupUpTime()).GetMilliSeconds() + 500) / 1000) : 0;
#endif

  ended = TRUE;

  int result = ::OSPPTransactionReportUsage(
      *this,                                /* In - Transaction handle */
      ospvCallDuration,                     /* In - Length of call */
#ifdef H323_NEW_OSP_API
      ospvStartTime,                        /* In - Call start time */
      ospvEndTime,                          /* In - Call end time */
      ospvAlertTime,                        /* In - Call alert time */
#endif
      ospvConnectionTime,                   /* In - Call connect time */
#ifdef H323_NEW_OSP_API
      ospvPostDialDelay > 0,                /* In - Is PDD Info present */
      ospvPostDialDelay,                    /* In - Post Dial Delay */
      ospvReleaseSource,                    /* In - EP that released the call */
      (unsigned char *)"",                  /* In - conference Id. Max 100 char long */
#endif
      lostSentPackets,                      /* In - Packets not received by peer */ 
      lostFractionSent,                     /* In - Fraction of packets not received by peer */
      lostReceivedPackets,                  /* In - Packets not received that were expected */
      lostFractionReceived,                 /* In - Fraction of packets expected but not received */
      0,                                    /* In/Out - Max size of detail log \ Actual size of detail log */
      NULL                                  /* Out - Pointer to detail log storage */
  );                          

  PTRACE_IF(2, result != 0, "OSP\tOSPPTransactionReportUsage returned status " << result); 
  PTRACE_IF(4, result == 0, "OSP\tOSPPTransactionReportUsage call with duration " << ospvCallDuration);
}

int OpalOSP::Transaction::Close()
{
  int stat = 0;
  if (IsOpen()) {

    // make sure the transaction is ended
    //if (!ended)
    //  CallEnd();

    // close the transaction
    stat = ::OSPPTransactionDelete(handle); 
    PTRACE_IF(2, stat != 0, "OSP\tOSPPTransactionDelete returned status " << stat); 
    handle = IllegalHandle;
  }

  return stat;
}

////////////////////////////////////////////////////////////////////////////////////
//
//  transaction authorisation functions

int OpalOSP::Transaction::Authorise(AuthorisationInfo & info, unsigned & numberOfDestinations)
{
  return Authorise(
    info.ospvSource,
    info.ospvSourceDevice,
    info.callingNumber,
    info.calledNumber,
    info.callID,
    numberOfDestinations
  );
}


int OpalOSP::Transaction::Authorise(const PString & ospvSource,
                                    const PString & ospvSourceDevice,
                                    const H225_AliasAddress & callingNumber,
                                    const H225_AliasAddress & calledNumber,
                                    const PBYTEArray & callID,
                                    unsigned & numberOfDestinations)
{
  int ospvCallingNumberFormat;
  PString ospvCallingNumber;
  if (!ConvertAliasToOSPString(callingNumber, ospvCallingNumberFormat, ospvCallingNumber)) {
    PTRACE(1, "OSP\tUnknown alias address type for calling number " << callingNumber);
    return -1;;
  }

  PString ospvCalledNumber;
  int ospvCalledNumberFormat;
  if (!ConvertAliasToOSPString(calledNumber, ospvCalledNumberFormat, ospvCalledNumber)) {
    PTRACE(1, "OSP\tUnknown alias address type for called number " << callingNumber);
    return -1;;
  }

  return Authorise(ospvSource, 
                   ospvSourceDevice,
                   ospvCallingNumber, 
                   ospvCallingNumberFormat,
                   ospvCalledNumber, 
                   ospvCalledNumberFormat,
                   callID,
                   numberOfDestinations);
}

int OpalOSP::Transaction::Authorise(const PString & ospvSource,
                                    const PString & _ospvSourceDevice,
                                    const PString & ospvCallingNumber,
                                    int ospvCallingNumberFormat,
                                    const PString & ospvCalledNumber,
                                    int ospvCalledNumberFormat,
                                    const PBYTEArray & callID,
                                    unsigned & numberOfDestinations)
{ 
  // make sure the provider is open
  if (!provider->IsOpen())
    return -1;

  // make sure the transaction is open
  if (!IsOpen()) {
    return -1 ;
  }

  PString ospvSourceDevice = _ospvSourceDevice;
  if (ospvSourceDevice.IsEmpty())
    ospvSourceDevice = ospvSource;

  ::OSPTCALLID * ospvCallID = OSPPCallIdNew(callID.GetSize(), (const BYTE *)callID);

  unsigned logSize = 0;

  PTRACE(4, "OSP\tMaking OSP Authorise request: src=" << ospvSource << ",srcDev=" << ospvSourceDevice << ",callingDn=" << ospvCallingNumber << ",calledDn=" << ospvCalledNumber);

  // perform the authorisation
  int stat = ::OSPPTransactionRequestAuthorisation(
      *this,
      (const char *)ospvSource,                          // source 
      (const char *)ospvSourceDevice,                    // source device
      (const char *)ospvCallingNumber,                   // calling number
      (OSPE_NUMBERING_FORMAT)ospvCallingNumberFormat,    // calling number format
      (const char *)ospvCalledNumber,                    // called number
      (OSPE_NUMBERING_FORMAT)ospvCalledNumberFormat,     // called number format
      user.IsEmpty() ? "" : (const char *)user,          // user identifier
      1,                                                 // number of call IDs
      &ospvCallID,                                       // call ID
      NULL,                                              // preferred destinations,
      &numberOfDestinations,                             // number of destinations,
      &logSize,                                          // detail log size,
      NULL                                               // detail log
  );

  ::OSPPCallIdDelete(&ospvCallID);

  PTRACE_IF(1, stat != 0, "OSP\tOSPPTransactionRequestAuthorisation returned " << stat);

  return stat;
}

static BOOL ValidateAddress(const H225_ArrayOf_AliasAddress & addresses, H225_AliasAddress & alias)
{
  PINDEX i;
  for (i = 0; i < addresses.GetSize(); ++i) {
    int fmt;
    PString str;
    if (OpalOSP::ConvertAliasToOSPString(addresses[i], fmt, str)) {
      alias = addresses[i];
      return TRUE;
    }
  }
  return FALSE;
}


BOOL OpalOSP::Transaction::AuthorisationInfo::Extract(const H323SignalPDU & setupPDU)
{
  if (setupPDU.m_h323_uu_pdu.m_h323_message_body.GetTag() != H225_H323_UU_PDU_h323_message_body::e_setup)
    return FALSE;

  const H225_Setup_UUIE & setup = setupPDU.m_h323_uu_pdu.m_h323_message_body;

  // must have a source call signalling address
  if (!setup.HasOptionalField(H225_Setup_UUIE::e_sourceCallSignalAddress)) 
    return FALSE;
  ospvSourceDevice = ospvSource = TransportAddressToOSPString(setup.m_sourceCallSignalAddress);

  // must have one or more source addresses
  // Use the Q.931 calling party number otherwise find a H.323 alias
  // that is a valid OSP target
  PString str;
  if (setupPDU.GetQ931().GetCallingPartyNumber(str))
    H323SetAliasAddress(str, callingNumber, H225_AliasAddress::e_dialedDigits);
  else if (!setup.HasOptionalField(H225_Setup_UUIE::e_sourceAddress) ||
           !ValidateAddress(setup.m_sourceAddress, callingNumber))
    return FALSE;

  // must have one or more destination addresses
  // Use the Q.931 called party number otherwise find a H.323 destination alias
  // that is a valid OSP target
  if (setupPDU.GetQ931().GetCalledPartyNumber(str))
    H323SetAliasAddress(str, calledNumber, H225_AliasAddress::e_dialedDigits);
  else if (!setup.HasOptionalField(H225_Setup_UUIE::e_destinationAddress) ||
      !ValidateAddress(setup.m_destinationAddress, calledNumber))
    return FALSE;

  // get the call identifier (make sure it has non-zero length)
  if (setup.m_callIdentifier.m_guid.GetSize() == 0)
    return FALSE;
  callID = setup.m_callIdentifier.m_guid;
  
  return TRUE;
}

BOOL OpalOSP::Transaction::AuthorisationInfo::Extract(const H225_AdmissionRequest & arq)
{
  // must have a source call signalling address
  if (!arq.HasOptionalField(H225_AdmissionRequest::e_srcCallSignalAddress)) 
    return FALSE;
  ospvSourceDevice = ospvSource = TransportAddressToOSPString(arq.m_srcCallSignalAddress);

  // must have one or more source addresses
  // pick the first one that is a valid OSP target
  if (!ValidateAddress(arq.m_srcInfo, callingNumber))
    return FALSE;

  // must have one or more destination addresses
  // pick the first one that is a valid OSP target
  if (!arq.HasOptionalField(H225_AdmissionRequest::e_destinationInfo) ||
      !ValidateAddress(arq.m_destinationInfo, calledNumber))
    return FALSE;

  // get the call identifier (make sure it has non-zero length)
  if (arq.m_callIdentifier.m_guid.GetSize() == 0)
    return FALSE;
  callID = arq.m_callIdentifier.m_guid;
  
  return TRUE;
}


////////////////////////////////////////////////////////////////////////////////////
//
//  transaction validation functions
//

int OpalOSP::Transaction::Validate(const ValidationInfo & info, BOOL & authorised, unsigned & timeLimit)
{
  return Validate(
    info.ospvSource,
    info.ospvDest,
    info.ospvSourceDevice,
    info.ospvDestDevice,
    info.callingNumber,
    info.calledNumber,
    info.callID,
    info.token,
    info.tokenAlgo,
    authorised,
    timeLimit
  );
}

int OpalOSP::Transaction::Validate(
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
)
{  
  PString calling;
  int callingFormat;
  ConvertAliasToOSPString(callingNumber, callingFormat, calling);

  PString called;
  int calledFormat;
  ConvertAliasToOSPString(calledNumber, calledFormat, called);

  return Validate(ospvSource, ospvDest, ospvSourceDevice, ospvDestDevice, 
                   callingFormat, calling, 
                   calledFormat,  called, 
                   callID, token, tokenAlgo, authorised, timeLimit);
}

int OpalOSP::Transaction::Validate(
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
      BOOL & isAuthorised,
      unsigned & timeLimit
    )
{
  // make sure the provider is open
  if (!provider->IsOpen())
    return -1;

  // make sure the transaction is open
  int stat = 0;
  if (!IsOpen()) {
    return -1 ;
  }

  unsigned int authorised = 0;
  unsigned int logSize = 0;

  stat = ::OSPPTransactionValidateAuthorisation(
      *this,
      (const char *)ospvSource,
      (const char *)ospvDest,
      (const char *)ospvSourceDevice,
      (const char *)ospvDestDevice,
      (const char *)ospvCallingNumber,
      (OSPE_NUMBERING_FORMAT)ospvCallingNumberFormat,
      (const char *)ospvCalledNumber,
      (OSPE_NUMBERING_FORMAT)ospvCalledNumberFormat,
      callID.GetSize(), (const BYTE *)callID,
      token.GetSize(), (const BYTE *)token,
      &authorised,
      &timeLimit,
      &logSize,
      NULL,
      tokenAlgo);

  isAuthorised = authorised != 0;
  return stat;
}

BOOL OpalOSP::Transaction::ValidationInfo::ExtractToken(const H225_ArrayOf_ClearToken & clearTokens)
{
  PINDEX tokenCount = clearTokens.GetSize();
  PINDEX i;
  for (i = 0; i < tokenCount; ++i) {
    H235_ClearToken & clearToken = clearTokens[i];
    if (clearToken.m_tokenOID == ETSIXMLTokenOID &&
        clearToken.HasOptionalField(H235_ClearToken::e_nonStandard) &&
        clearToken.m_nonStandard.m_nonStandardIdentifier == ETSIXMLTokenOID) 
    {
      token = clearToken.m_nonStandard.m_data;
      return TRUE;
    }
  }
  return FALSE;
}

BOOL OpalOSP::Transaction::ValidationInfo::Extract(const H323SignalPDU & setupPDU)
{
  if (setupPDU.m_h323_uu_pdu.m_h323_message_body.GetTag() != H225_H323_UU_PDU_h323_message_body::e_setup)
    return FALSE;

  const H225_Setup_UUIE & setup = setupPDU.m_h323_uu_pdu.m_h323_message_body;

  // must have a source call signalling address
  if (!setup.HasOptionalField(H225_Setup_UUIE::e_sourceCallSignalAddress)) 
    return FALSE;
  ospvSourceDevice = ospvSource = TransportAddressToOSPString(setup.m_sourceCallSignalAddress);

  // must have one or more source addresses
  // Use the Q.931 calling party number otherwise find a H.323 alias
  // that is a valid OSP target
  PString str;
  if (setupPDU.GetQ931().GetCallingPartyNumber(str))
    H323SetAliasAddress(str, callingNumber, H225_AliasAddress::e_dialedDigits);
  else if (!setup.HasOptionalField(H225_Setup_UUIE::e_sourceAddress) ||
      !ValidateAddress(setup.m_sourceAddress, callingNumber))
    return FALSE;

  // use destination call signalling address if present
  if (setup.HasOptionalField(H225_Setup_UUIE::e_destCallSignalAddress)) 
    ospvDestDevice = ospvDest = TransportAddressToOSPString(setup.m_destCallSignalAddress);

  // must have one or more destination addresses
  // Use the Q.931 called party number otherwise find a H.323 destination alias
  // that is a valid OSP target
  if (setupPDU.GetQ931().GetCalledPartyNumber(str))
    H323SetAliasAddress(str, calledNumber, H225_AliasAddress::e_dialedDigits);
  else if (!setup.HasOptionalField(H225_Setup_UUIE::e_destinationAddress) ||
           !ValidateAddress(setup.m_destinationAddress, calledNumber))
    return FALSE;

  // get the call identifier (make sure it has non-zero length)
  if (setup.m_callIdentifier.m_guid.GetSize() == 0)
    return FALSE;
  callID = setup.m_callIdentifier.m_guid;

  // get the token
  return setup.HasOptionalField(H225_Setup_UUIE::e_tokens) && ExtractToken(setup.m_tokens);
}

BOOL OpalOSP::Transaction::ValidationInfo::Extract(const H225_AdmissionRequest & arq)
{
  // must have a source call signalling address
  if (!arq.HasOptionalField(H225_AdmissionRequest::e_srcCallSignalAddress)) 
    return FALSE;
  PIPSocket::Address addr;
  WORD port;
  H323TransportAddress taddr(arq.m_srcCallSignalAddress);
  if (!taddr.GetIpAndPort(addr, port))
    return FALSE;
  ospvSourceDevice = ospvSource = IpAddressPortToOSPString(addr, port);

  // must have one or more source addresses
  // pick the first one that is a valid OSP target
  if (!ValidateAddress(arq.m_srcInfo, callingNumber))
    return FALSE;

  // must have one or more destination addresses
  // pick the first one that is a valid OSP target
  if (!arq.HasOptionalField(H225_AdmissionRequest::e_destinationInfo) ||
      !ValidateAddress(arq.m_destinationInfo, calledNumber))
    return FALSE;

  // get the call identifier (make sure it has non-zero length)
  if (arq.m_callIdentifier.m_guid.GetSize() == 0)
    return FALSE;
  callID = arq.m_callIdentifier.m_guid;
  
  return TRUE;
}


////////////////////////////////////////////////////////////////////////////////////
//
//  transaction destination functions
//

int OpalOSP::Transaction::GetFirstDestination(DestinationInfo & info)
{
  PString destAddress;
  PString calledNumber;
  PString callingNumber;

  int result = GetFirstDestination(
      info.timeLimit,
      info.callID,
      calledNumber,
      callingNumber,
      destAddress,
      info.destination,
      info.token
  );

  if (result != 0)
    return result;

  info.destinationAddress = OSPStringToAddress(destAddress, H323EndPoint::DefaultTcpPort);
  H323SetAliasAddress(calledNumber, info.calledNumber, H225_AliasAddress::e_dialedDigits);

  info.hasCallingNumber = !callingNumber.IsEmpty();
  if (info.hasCallingNumber)
    H323SetAliasAddress(callingNumber, info.callingNumber, H225_AliasAddress::e_dialedDigits);

  return 0;
}

int OpalOSP::Transaction::GetFirstDestination(unsigned & timeLimit,
                                              PBYTEArray & callID,
                                              PString & calledNumber,
                                              PString & callingNumber,
                                              PString & destAddress,
                                              PString & destDevice,
                                              PBYTEArray & token)
{
  if (!CheckOpenedAndNotEnded("get first destination"))
    return -1;

  callID.SetSize(CALLID_SIZE);
  unsigned callIDSize = callID.GetSize();

  calledNumber.SetSize(CALLED_NUMBER_SIZE+1);
  callingNumber.SetSize(CALLING_NUMBER_SIZE+1);
  destAddress.SetSize(DESTINATION_SIZE+1);
  destDevice.SetSize(DEVICE_SIZE+1);

  token.SetSize(TOKEN_SIZE);
  unsigned tokenSize = token.GetSize();

  int stat = ::OSPPTransactionGetFirstDestination(
      *this,                             /* In  - Transaction handle */
      0,                                 /* In  - Max size for timestamp string */
      NULL,                              /* Out - Valid After time in string format */
      NULL,                              /* Out - Valid Until time in string format */
      &timeLimit,                        /* Out - Number of seconds call is authorised for */
      &callIDSize,                       /* In/Out - Max size for CallId string Actual size of CallId string */
      callID.GetPointer(),               /* Out - Call Id string */
      calledNumber.GetSize(),            /* In - Max size of called number */
      calledNumber.GetPointer(),         /* Out - Called number string */
#ifdef H323_NEW_OSP_API
      callingNumber.GetSize(),           /* In - Max size of calling number */
      callingNumber.GetPointer(),        /* Out - Calling number string */
#endif
      destAddress.GetSize(),             /* In - Max size of destination string */
      destAddress.GetPointer(),          /* Out - Destination string */
      destDevice.GetSize(),              /* In - Max size of dest device string */
      destDevice.GetPointer(),           /* Out - Dest device string */
      &tokenSize,                        /* In/Out - Max size of token string Actual size of token string */ 
      token.GetPointer()                 /* Out - Token string */
 );         

  callID.SetSize(callIDSize);
  calledNumber.MakeMinimumSize();
  callingNumber.MakeMinimumSize();
  destAddress.MakeMinimumSize();
  destDevice.MakeMinimumSize();
  token.SetSize(tokenSize);

  return stat;
}

int OpalOSP::Transaction::GetNextDestination(int reason, DestinationInfo & info)
{
  PString destAddress;
  PString calledNumber;
  PString callingNumber;

  int result = GetNextDestination(
      reason,
      info.timeLimit,
      info.callID,
      calledNumber,
      callingNumber,
      destAddress,
      info.destination,
      info.token
  );

  if (result != 0)
    return result;

  info.destinationAddress = OSPStringToAddress(destAddress, H323EndPoint::DefaultTcpPort);
  H323SetAliasAddress(calledNumber, info.calledNumber, H225_AliasAddress::e_dialedDigits);

  info.hasCallingNumber = !callingNumber.IsEmpty();
  if (info.hasCallingNumber)
    H323SetAliasAddress(callingNumber, info.callingNumber, H225_AliasAddress::e_dialedDigits);

  return 0;
}

int OpalOSP::Transaction::GetNextDestination(int reason, 
                                      unsigned & timeLimit,
                                    PBYTEArray & callID,
                                       PString & calledNumber,
                                       PString & callingNumber,
                                       PString & destAddress,
                                       PString & destDevice,
                                    PBYTEArray & token)
{
  if (!CheckOpenedAndNotEnded("get first destination"))
    return -1;

  callID.SetSize(CALLID_SIZE);
  unsigned callIDSize = callID.GetSize();

  calledNumber.SetSize(CALLED_NUMBER_SIZE+1);
  callingNumber.SetSize(CALLING_NUMBER_SIZE+1);
  destAddress.SetSize(DESTINATION_SIZE+1);
  destDevice.SetSize(DEVICE_SIZE+1);

  token.SetSize(TOKEN_SIZE);
  unsigned tokenSize = token.GetSize();

  int stat = ::OSPPTransactionGetNextDestination(
      *this,                                /* In - Transaction handle */
      (OSPEFAILREASON)reason,               /* In - Failure code */
      0,                                    /* In - Max size of timestamp string */
      NULL,                                 /* Out - Valid after time string */
      NULL,                                 /* Out - Valid until time string */
      &timeLimit,                           /* Out - Number of seconds call is authorised for */
      &callIDSize,                          /* In - Max size of call id string */
      callID.GetPointer(),                  /* Out - Call Id string */
      calledNumber.GetSize(),               /* In - Max size of called number */
      calledNumber.GetPointer(),            /* Out - Called number string */
#ifdef H323_NEW_OSP_API
      callingNumber.GetSize(),              /* In - Max size of calling number */
      callingNumber.GetPointer(),           /* Out - Calling number string */
#endif
      destAddress.GetSize(),                /* In - Max size of destination string */
      destAddress.GetPointer(),             /* Out - Destination string */
      destDevice.GetSize(),                 /* In - Max size of dest device string */
      destDevice.GetPointer(),              /* Out - Dest device string */
      &tokenSize,                           /* In/Out - Max size of token string Actual size of token string */
      token.GetPointer()                    /* Out - Token string */
  );                               

  callID.SetSize(callIDSize);
  calledNumber.MakeMinimumSize();
  callingNumber.MakeMinimumSize();
  destAddress.MakeMinimumSize();
  destDevice.MakeMinimumSize();
  token.SetSize(tokenSize);

  return stat;
}

void OpalOSP::Transaction::DestinationInfo::InsertToken(H225_ArrayOf_ClearToken & clearTokens, BOOL useCiscoBug)
{
  PINDEX tokenCount = clearTokens.GetSize();
  clearTokens.SetSize(tokenCount+1);
  H235_ClearToken & clearToken = clearTokens[tokenCount];
  clearToken.m_tokenOID = ETSIXMLTokenOID;
  clearToken.IncludeOptionalField(H235_ClearToken::e_nonStandard);
  clearToken.m_nonStandard.m_nonStandardIdentifier = ETSIXMLTokenOID;

  if (!useCiscoBug) {
    clearToken.m_nonStandard.m_data = token;
  } else {
    PASN_OctetString & destToken = clearToken.m_nonStandard.m_data;
    PINDEX tokenSize = token.GetSize();
    destToken.SetSize(token.GetSize()+3);
    destToken[0] = 0;
    destToken[1] = (BYTE)(0x80+(tokenSize>>8));
    destToken[2] = (BYTE)tokenSize;
    memcpy(&destToken[3], &token[0], tokenSize);
  }
}

BOOL OpalOSP::Transaction::DestinationInfo::Insert(H323SignalPDU & setupPDU, BOOL useCiscoBug)
{
  if (setupPDU.m_h323_uu_pdu.m_h323_message_body.GetTag() != H225_H323_UU_PDU_h323_message_body::e_setup)
    return FALSE;

  H225_Setup_UUIE & setup = setupPDU.m_h323_uu_pdu.m_h323_message_body;

  return Insert(setup, useCiscoBug);
}

BOOL OpalOSP::Transaction::DestinationInfo::Insert(H225_Setup_UUIE & setup, BOOL useCiscoBug)
{
  // insert the OSP token into the PDU
  setup.IncludeOptionalField(H225_Setup_UUIE::e_tokens);
  InsertToken(setup.m_tokens, useCiscoBug);

  // set the destination address array to the called number
  setup.IncludeOptionalField(H225_Setup_UUIE::e_destinationAddress);
  setup.m_destinationAddress.SetSize(1);
  setup.m_destinationAddress[0] = calledNumber;

  return TRUE;
}

BOOL OpalOSP::Transaction::DestinationInfo::Insert(H225_AdmissionConfirm & acf, BOOL useCiscoBug)
{
  // insert the OSP token into the PDU
  acf.IncludeOptionalField(H225_AdmissionConfirm::e_tokens);
  InsertToken(acf.m_tokens, useCiscoBug);

  // set the destinationInfo field to the called number
  destinationAddress.SetPDU(acf.m_destCallSignalAddress);

  // set the destCallSignalAddress field to the destination address
  acf.IncludeOptionalField(H225_AdmissionConfirm::e_destinationInfo);
  acf.m_destinationInfo.SetSize(1);
  acf.m_destinationInfo[0] = calledNumber;

  return TRUE;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////

#endif // H323_TRANSNEXUS_OSP

// end of file


