# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200508-06.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(19439);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200508-06");
 script_cve_id("CVE-2005-2102", "CVE-2005-2103");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200508-06
(Gaim: Remote execution of arbitrary code)


    Brandon Perry discovered that Gaim is vulnerable to a heap-based
    buffer overflow when handling away messages (CVE-2005-2103).
    Furthermore, Daniel Atallah discovered a vulnerability in the handling
    of file transfers (CVE-2005-2102).
  
Impact

    A remote attacker could create a specially crafted away message
    which, when viewed by the target user, could lead to the execution of
    arbitrary code. Also, an attacker could send a file with a non-UTF8
    filename to a user, which would result in a Denial of Service.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-2102
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-2103


Solution: 
    All Gaim users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-im/gaim-1.5.0"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200508-06] Gaim: Remote execution of arbitrary code");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Gaim: Remote execution of arbitrary code');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-im/gaim", unaffected: make_list("ge 1.5.0"), vulnerable: make_list("lt 1.5.0")
)) { security_hole(0); exit(0); }
