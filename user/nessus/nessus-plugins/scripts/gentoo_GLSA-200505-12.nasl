# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200505-12.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(18271);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200505-12");
 script_cve_id("2005-1409", "2005-1410");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200505-12
(PostgreSQL: Multiple vulnerabilities)


    PostgreSQL gives public EXECUTE access to a number of character
    conversion routines, but doesn\'t validate the given arguments
    (CVE-2005-1409). It has also been reported that the contrib/tsearch2
    module of PostgreSQL misdeclares the return value of some functions as
    "internal" (CVE-2005-1410).
  
Impact

    An attacker could call the character conversion routines with
    specially setup arguments to crash the backend process of PostgreSQL or
    to potentially gain administrator rights. A malicious user could also
    call the misdeclared functions of the contrib/tsearch2 module,
    resulting in a Denial of Service or other, yet uninvestigated, impacts.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://www.postgresql.org/about/news.315
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=2005-1409
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=2005-1410
    http://www.postgresql.org/about/news.315


Solution: 
    All PostgreSQL users should update to the latest available version
    and follow the guide at http://www.postgresql.o
    rg/about/news.315
    # emerge --sync
    # emerge --ask --oneshot --verbose dev-db/postgresql
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200505-12] PostgreSQL: Multiple vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'PostgreSQL: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "dev-db/postgresql", unaffected: make_list("rge 7.4.7-r2", "rge 8.0.1-r3", "ge 8.0.2-r1"), vulnerable: make_list("lt 8.0.2-r1")
)) { security_warning(0); exit(0); }
