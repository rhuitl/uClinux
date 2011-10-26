# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200610-02.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(22506);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200610-02");
 script_cve_id("CVE-2006-3311", "CVE-2006-3587", "CVE-2006-3588");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200610-02
(Adobe Flash Player: Arbitrary code execution)


    The Adobe Flash Player contains multiple unspecified vulnerabilities.
  
Impact

    An attacker could entice a user to view a malicious Flash file and
    execute arbitrary code with the rights of the user running the player.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://www.adobe.com/support/security/bulletins/apsb06-11.html
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-3311
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-3587
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-3588


Solution: 
    All Adobe Flash Player users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-www/netscape-flash-7.0.68"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200610-02] Adobe Flash Player: Arbitrary code execution");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Adobe Flash Player: Arbitrary code execution');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-www/netscape-flash", unaffected: make_list("ge 7.0.68"), vulnerable: make_list("lt 7.0.68")
)) { security_warning(0); exit(0); }
