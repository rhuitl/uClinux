# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200404-09.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14474);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200404-09");
 script_cve_id("CVE-2004-0371");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200404-09
(Cross-realm trust vulnerability in Heimdal)


    Heimdal does not properly perform certain consistency checks for
    cross-realm requests, which allows remote attackers with control of a realm
    to impersonate others in the cross-realm trust path.
  
Impact

    Remote attackers with control of a realm may be able to impersonate other
    users in the cross-realm trust path.
  
Workaround

    A workaround is not currently known for this issue. All users are advised
    to upgrade to the latest version of the affected package.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0371


Solution: 
    Heimdal users should upgrade to version 0.6.1 or later:
    # emerge sync
    # emerge -pv ">=app-crypt/heimdal-0.6.1"
    # emerge ">=app-crypt/heimdal-0.6.1"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200404-09] Cross-realm trust vulnerability in Heimdal");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Cross-realm trust vulnerability in Heimdal');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "app-crypt/heimdal", unaffected: make_list("ge 0.6.1"), vulnerable: make_list("le 0.6.0")
)) { security_warning(0); exit(0); }
