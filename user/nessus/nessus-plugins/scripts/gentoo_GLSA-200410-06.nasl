# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200410-06.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(15444);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200410-06");
 script_cve_id("CVE-2004-0923");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200410-06
(CUPS: Leakage of sensitive information)


    When printing to a SMB-shared printer requiring authentication, CUPS leaks
    the user name and password to a logfile.
  
Impact

    A local user could gain knowledge of sensitive authentication data.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0923


Solution: 
    All CUPS users should upgrade to the latest version:
    # emerge sync
    # emerge -pv ">=net-print/cups-1.1.20-r3"
    # emerge ">=net-print/cups-1.1.20-r3"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200410-06] CUPS: Leakage of sensitive information");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'CUPS: Leakage of sensitive information');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-print/cups", unaffected: make_list("rge 1.1.20-r3", "ge 1.1.21-r1"), vulnerable: make_list("le 1.1.20-r2", "eq 1.1.21")
)) { security_warning(0); exit(0); }
