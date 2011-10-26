/*
 * svcctrl.cxx
 *
 * H.225 Service Control protocol handler
 *
 * Open H323 Library
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
 * The Original Code is Open H323 Library.
 *
 * The Initial Developer of the Original Code is Equivalence Pty. Ltd.
 *
 * Contributor(s): ______________________________________.
 *
 * $Log: svcctrl.cxx,v $
 * Revision 1.2  2006/05/16 11:37:11  shorne
 * Added ability to detect type of service control
 *
 * Revision 1.1  2003/04/01 01:06:28  robertj
 * Split service control handlers from H.225 RAS header.
 *
 */

#include <ptlib.h>

#ifdef __GNUC__
#pragma implementation "svcctrl.h"
#endif

#include "svcctrl.h"

#include "h323ep.h"
#include "h323pdu.h"
#include "h248.h"


#define new PNEW


/////////////////////////////////////////////////////////////////////////////

H323ServiceControlSession::H323ServiceControlSession()
{
}


PString H323ServiceControlSession::GetServiceControlType() const
{
  return GetClass();
}


/////////////////////////////////////////////////////////////////////////////

H323HTTPServiceControl::H323HTTPServiceControl(const PString & u)
  : url(u)
{
}


H323HTTPServiceControl::H323HTTPServiceControl(const H225_ServiceControlDescriptor & contents)
{
  OnReceivedPDU(contents);
}


BOOL H323HTTPServiceControl::IsValid() const
{
  return !url.IsEmpty();
}


PString H323HTTPServiceControl::GetServiceControlType() const
{
  return url;
}


BOOL H323HTTPServiceControl::OnReceivedPDU(const H225_ServiceControlDescriptor & contents)
{
  if (contents.GetTag() != H225_ServiceControlDescriptor::e_url)
    return FALSE;

  const PASN_IA5String & pdu = contents;
  url = pdu;
  return TRUE;
}


BOOL H323HTTPServiceControl::OnSendingPDU(H225_ServiceControlDescriptor & contents) const
{
  contents.SetTag(H225_ServiceControlDescriptor::e_url);
  PASN_IA5String & pdu = contents;
  pdu = url;

  return TRUE;
}


void H323HTTPServiceControl::OnChange(unsigned type,
                                      unsigned sessionId,
                                      H323EndPoint & endpoint,
                                      H323Connection * /*connection*/) const
{
  PTRACE(2, "SvcCtrl\tOnChange HTTP service control " << url);

  endpoint.OnHTTPServiceControl(type, sessionId, url);
}


/////////////////////////////////////////////////////////////////////////////

H323H248ServiceControl::H323H248ServiceControl()
{
}


H323H248ServiceControl::H323H248ServiceControl(const H225_ServiceControlDescriptor & contents)
{
  OnReceivedPDU(contents);
}


BOOL H323H248ServiceControl::OnReceivedPDU(const H225_ServiceControlDescriptor & contents)
{
  if (contents.GetTag() != H225_ServiceControlDescriptor::e_signal)
    return FALSE;

  const H225_H248SignalsDescriptor & pdu = contents;

  H248_SignalsDescriptor signal;
  if (!pdu.DecodeSubType(signal))
    return FALSE;

  return OnReceivedPDU(signal);
}


BOOL H323H248ServiceControl::OnSendingPDU(H225_ServiceControlDescriptor & contents) const
{
  contents.SetTag(H225_ServiceControlDescriptor::e_signal);
  H225_H248SignalsDescriptor & pdu = contents;

  H248_SignalsDescriptor signal;

  pdu.EncodeSubType(signal);

  return OnSendingPDU(signal);
}


BOOL H323H248ServiceControl::OnReceivedPDU(const H248_SignalsDescriptor & descriptor)
{
  for (PINDEX i = 0; i < descriptor.GetSize(); i++) {
    if (!OnReceivedPDU(descriptor[i]))
      return FALSE;
  }

  return TRUE;
}


BOOL H323H248ServiceControl::OnSendingPDU(H248_SignalsDescriptor & descriptor) const
{
  PINDEX last = descriptor.GetSize();
  descriptor.SetSize(last+1);
  return OnSendingPDU(descriptor[last]);
}


/////////////////////////////////////////////////////////////////////////////

H323CallCreditServiceControl::H323CallCreditServiceControl(const PString & amt,
                                                           BOOL m,
                                                           unsigned dur)
  : amount(amt),
    mode(m),
    durationLimit(dur)
{
}


H323CallCreditServiceControl::H323CallCreditServiceControl(const H225_ServiceControlDescriptor & contents)
{
  OnReceivedPDU(contents);
}


BOOL H323CallCreditServiceControl::IsValid() const
{
  return !amount || durationLimit > 0;
}


BOOL H323CallCreditServiceControl::OnReceivedPDU(const H225_ServiceControlDescriptor & contents)
{
  if (contents.GetTag() != H225_ServiceControlDescriptor::e_callCreditServiceControl)
    return FALSE;

  const H225_CallCreditServiceControl & credit = contents;

  if (credit.HasOptionalField(H225_CallCreditServiceControl::e_amountString))
    amount = credit.m_amountString;

  if (credit.HasOptionalField(H225_CallCreditServiceControl::e_billingMode))
    mode = credit.m_billingMode.GetTag() == H225_CallCreditServiceControl_billingMode::e_debit;
  else
    mode = TRUE;

  if (credit.HasOptionalField(H225_CallCreditServiceControl::e_callDurationLimit))
    durationLimit = credit.m_callDurationLimit;
  else
    durationLimit = 0;

  return TRUE;
}


BOOL H323CallCreditServiceControl::OnSendingPDU(H225_ServiceControlDescriptor & contents) const
{
  contents.SetTag(H225_ServiceControlDescriptor::e_callCreditServiceControl);
  H225_CallCreditServiceControl & credit = contents;

  if (!amount) {
    credit.IncludeOptionalField(H225_CallCreditServiceControl::e_amountString);
    credit.m_amountString = amount;

    credit.IncludeOptionalField(H225_CallCreditServiceControl::e_billingMode);
    credit.m_billingMode.SetTag(mode ? H225_CallCreditServiceControl_billingMode::e_debit
                                     : H225_CallCreditServiceControl_billingMode::e_credit);
  }

  if (durationLimit > 0) {
    credit.IncludeOptionalField(H225_CallCreditServiceControl::e_callDurationLimit);
    credit.m_callDurationLimit = durationLimit;
    credit.IncludeOptionalField(H225_CallCreditServiceControl::e_enforceCallDurationLimit);
    credit.m_enforceCallDurationLimit = TRUE;
  }

  return !amount || durationLimit > 0;
}


void H323CallCreditServiceControl::OnChange(unsigned /*type*/,
                                             unsigned /*sessionId*/,
                                             H323EndPoint & endpoint,
                                             H323Connection * connection) const
{
  PTRACE(2, "SvcCtrl\tOnChange Call Credit service control "
         << amount << (mode ? " debit " : " credit ") << durationLimit);

  endpoint.OnCallCreditServiceControl(amount, mode, durationLimit);
  if (durationLimit > 0 && connection != NULL)
    connection->SetEnforcedDurationLimit(durationLimit);
}


/////////////////////////////////////////////////////////////////////////////
