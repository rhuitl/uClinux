# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200502-24.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(17138);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200502-24");
 script_cve_id("CVE-2004-1004", "CVE-2004-1005", "CVE-2004-1092", "CVE-2004-1176");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200502-24
(Midnight Commander: Multiple vulnerabilities)


    Midnight Commander contains several format string vulnerabilities
    (CVE-2004-1004), buffer overflows (CVE-2004-1005), a memory
    deallocation error (CVE-2004-1092) and a buffer underflow
    (CVE-2004-1176).
  
Impact

    An attacker could exploit these vulnerabilities to execute
    arbitrary code with the permissions of the user running Midnight
    Commander or cause Denial of Service by freeing unallocated memory.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-1004
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-1005
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-1092
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-1176


Solution: 
    All Midnight Commander users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-misc/mc-4.6.0-r13"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200502-24] Midnight Commander: Multiple vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Midnight Commander: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "app-misc/mc", unaffected: make_list("ge 4.6.0-r13"), vulnerable: make_list("lt 4.6.0-r13")
)) { security_warning(0); exit(0); }
