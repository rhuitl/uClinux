# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200609-16.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(22460);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200609-16");
 script_cve_id("CVE-2006-4299", "CVE-2006-4602");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200609-16
(Tikiwiki: Arbitrary command execution)


    A vulnerability in jhot.php allows for an unrestricted file upload to
    the img/wiki/ directory. Additionally, an XSS exists in the highlight
    parameter of tiki-searchindex.php.
  
Impact

    An attacker could execute arbitrary code with the rights of the user
    running the web server by uploading a file and executing it via a
    filepath parameter. The XSS could be exploited to inject and execute
    malicious script code or to steal cookie-based authentication
    credentials, potentially compromising the victim\'s browser.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-4299
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-4602


Solution: 
    All Tikiwiki users should upgrade to the latest version:
    # emerge --sync
    # emerge --oneshot --verbose --ask ">=www-apps/tikiwiki-1.9.5"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200609-16] Tikiwiki: Arbitrary command execution");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Tikiwiki: Arbitrary command execution');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "www-apps/tikiwiki", unaffected: make_list("ge 1.9.5"), vulnerable: make_list("lt 1.9.5")
)) { security_hole(0); exit(0); }
