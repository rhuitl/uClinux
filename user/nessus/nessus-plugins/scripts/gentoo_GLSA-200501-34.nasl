# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200501-34.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(16425);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200501-34");
 script_cve_id("CVE-2005-0129", "CVE-2005-0130", "CVE-2005-0131");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200501-34
(Konversation: Various vulnerabilities)


    Wouter Coekaerts has discovered three vulnerabilites within
    Konversation:
    The Server::parseWildcards function, which
    is used by the "Quick Buttons", does not properly handle variable
    expansion (CVE-2005-0129).
    Perl scripts included with
    Konversation do not properly escape shell metacharacters
    (CVE-2005-0130).
    The \'Nick\' and \'Password\' fields in the Quick
    Connect dialog can be easily confused (CVE-2005-0131).
  
Impact

    A malicious server could create specially-crafted channels, which
    would exploit certain flaws in Konversation, potentially leading to the
    execution of shell commands. A user could also unintentionally input
    their password into the \'Nick\' field in the Quick Connect dialog,
    exposing his password to IRC users, and log files.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0129
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0130
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0131
    http://www.kde.org/info/security/advisory-20050121-1.txt


Solution: 
    All Konversation users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-irc/konversation-0.15.1"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200501-34] Konversation: Various vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Konversation: Various vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-irc/konversation", unaffected: make_list("ge 0.15.1"), vulnerable: make_list("lt 0.15.1")
)) { security_warning(0); exit(0); }
