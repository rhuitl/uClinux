/*
 * pdns.h
 *
 * PWLib library for ENUM lookup
 *
 * Portable Windows Library
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
 * The Original Code is Portable Windows Library.
 *
 * The Initial Developer of the Original Code is Post Increment
 *
 * Contributor(s): ______________________________________.
 *
 * $Log: enum.h,v $
 * Revision 1.5  2005/11/30 12:47:37  csoutheren
 * Removed tabs, reformatted some code, and changed tags for Doxygen
 *
 * Revision 1.4  2005/08/31 23:55:48  csoutheren
 * Fixed typo
 *
 * Revision 1.3  2005/08/31 05:55:03  shorne
 * Reworked ENUM to craigs' exacting requirements
 *
 * Revision 1.2  2005/08/31 04:07:52  shorne
 * added ability to set ENUM Servers at runtime
 *
 * Revision 1.1  2004/05/31 13:56:37  csoutheren
 * Added implementation of ENUM resolution of E.164 numbers by DNS
 *
 */

#if P_DNS

#ifndef _PENUM_H
#define _PENUM_H

#ifdef P_USE_PRAGMA
#pragma interface
#endif

#include <ptclib/pdns.h>

namespace PDNS {

#ifndef NAPTR_SRV
#define NAPTR_SRV 35
#endif

///////////////////////////////////////////////////////////////////////////

class NAPTRRecord : public PObject
{
  PCLASSINFO(NAPTRRecord, PObject);
  public:
    Comparison Compare(const PObject & obj) const;
    void PrintOn(ostream & strm) const;

    WORD order;
    WORD preference;
    PString flags;
    PString service;
    PString regex;
    PString replacement;
};

PDECLARE_SORTED_LIST(NAPTRRecordList, PDNS::NAPTRRecord)
  public:
    void PrintOn(ostream & strm) const;

    NAPTRRecord * GetFirst(const char * service = NULL);
    NAPTRRecord * GetNext(const char * service = NULL);

    PDNS::NAPTRRecord * HandleDNSRecord(PDNS_RECORD dnsRecord, PDNS_RECORD results);

    void UnlockOrder()
    { orderLocked = FALSE; }

  protected:
    PINDEX     currentPos;
    int        lastOrder;
    BOOL       orderLocked;
};

inline BOOL GetRecords(const PString & domain, NAPTRRecordList & recordList)
{ return Lookup<NAPTR_SRV, NAPTRRecordList, NAPTRRecord>(domain, recordList); }

/**
  * Set the default ENUM domain search list 
  */
void SetENUMServers(const PStringArray & serverlist);

/**
  * Perform a lookup of the specified DN using the specified service
  * and domain list. Returns the resultant URL
  *
  * @return TRUE if the DN could be resolved, else FALSE
  */
BOOL ENUMLookup(
                const PString & dn,             ///< DN to lookup
                const PString & service,        ///< ENUM service to use
                const PStringArray & domains,   ///< list of ENUM domains to search
                PString & URL                   ///< resolved URL, if return value is TRUE
);

/**
  * Perform a lookup of the specified DN using the specified service
  * using the default domain list. Returns the resultant URL.
  *
  * This function uses the default domain list, which can be set by the SetENUMServers function
  *
  * @return TRUE if the DN could be resolved, else FALSE
  */
BOOL ENUMLookup(const PString & dn,             ///< DN to lookup
                const PString & service,        ///< ENUM service to use
                PString & URL                   ///< resolved URL, if return value is TRUE
);                                              

}; // namespace PDNS

#endif // _PENUM_H
#endif // P_DNS

// End Of File ///////////////////////////////////////////////////////////////
