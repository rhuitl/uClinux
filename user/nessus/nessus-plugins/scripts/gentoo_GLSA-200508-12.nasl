# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200508-12.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(19485);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200508-12");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200508-12
(Evolution: Format string vulnerabilities)


    Ulf Harnhammar discovered that Evolution is vulnerable to format
    string bugs when viewing attached vCards and when displaying contact
    information from remote LDAP servers or task list data from remote
    servers (CVE-2005-2549). He also discovered that Evolution fails to
    handle special calendar entries if the user switches to the Calendars
    tab (CVE-2005-2550).
  
Impact

    An attacker could attach specially crafted vCards to emails or
    setup malicious LDAP servers or calendar entries which would trigger
    the format string vulnerabilities when viewed or accessed from
    Evolution. This could potentially result in the execution of arbitrary
    code with the rights of the user running Evolution.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-2549
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-2550
    http://www.sitic.se/eng/advisories_and_recommendations/sa05-001.html


Solution: 
    All Evolution users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=mail-client/evolution-2.2.3-r3"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200508-12] Evolution: Format string vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Evolution: Format string vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "mail-client/evolution", unaffected: make_list("ge 2.2.3-r3"), vulnerable: make_list("lt 2.2.3-r3")
)) { security_warning(0); exit(0); }
