// H460.h:
/*
 * Virteos H.460 Implementation for the OpenH323 Project.
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
 * The Original Code is derived from and used in conjunction with the 
 * OpenH323 Project (www.openh323.org/)
 *
 * The Initial Developer of the Original Code is ISVO (Asia) Pte Ltd.
 *
 *
 * Contributor(s): ______________________________________.
 *
*/


#ifdef P_USE_PRAGMA
#pragma interface
#endif

class H460_MessageType
{
  public:
    enum {
      e_gatekeeperRequest,
      e_gatekeeperConfirm,
      e_gatekeeperReject,
      e_registrationRequest,
      e_registrationConfirm, 
      e_registrationReject,
      e_admissionRequest,
      e_admissionConfirm,
      e_admissionReject,
      e_locationRequest,
      e_locationConfirm,
      e_locationReject,
      e_nonStandardMessage,
      e_serviceControlIndication,
      e_serviceControlResponse,
	  e_setup,
      e_callProceeding,
      e_connect,
      e_alerting,
      e_facility,
	  e_releaseComplete,
	  e_unallocated
    };
};

