# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200412-26.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(16068);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200412-26");
 script_cve_id("CVE-2004-0915", "CVE-2004-1062");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200412-26
(ViewCVS: Information leak and XSS vulnerabilities)


    The tar export functions in ViewCVS bypass the \'hide_cvsroot\' and
    \'forbidden\' settings and therefore expose information that should be
    kept secret (CVE-2004-0915). Furthermore, some error messages in
    ViewCVS do not filter user-provided information, making it vulnerable
    to a cross-site scripting attack (CVE-2004-1062).
  
Impact

    By using the tar export functions, a remote attacker could access
    information that is configured as restricted. Through the use of a
    malicious request, an attacker could also inject and execute malicious
    script code, potentially compromising another user\'s browser.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0915
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-1062


Solution: 
    All ViewCVS users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-apps/viewcvs-0.9.2_p20041207-r1"
  

Risk factor : Low
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200412-26] ViewCVS: Information leak and XSS vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'ViewCVS: Information leak and XSS vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "www-apps/viewcvs", unaffected: make_list("ge 0.9.2_p20041207-r1"), vulnerable: make_list("le 0.9.2_p20041207")
)) { security_warning(0); exit(0); }
