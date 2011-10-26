# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200603-22.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(21129);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200603-22");
 script_cve_id("CVE-2006-0207", "CVE-2006-0208");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200603-22
(PHP: Format string and XSS vulnerabilities)


    Stefan Esser of the Hardened PHP project has reported a few
    vulnerabilities found in PHP:
    Input passed to the session
    ID in the session extension isn\'t properly sanitised before being
    returned to the user via a "Set-Cookie" HTTP header, which can contain
    arbitrary injected data.
    A format string error while
    processing error messages using the mysqli extension in version 5.1 and
    above.
  
Impact

    By sending a specially crafted request, a remote attacker can
    exploit this vulnerability to inject arbitrary HTTP headers, which will
    be included in the response sent to the user. The format string
    vulnerability may be exploited to execute arbitrary code.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-0207
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-0208
    http://www.hardened-php.net/advisory_022006.112.html
    http://www.hardened-php.net/advisory_012006.113.html


Solution: 
    All PHP 5.x users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-lang/php-5.1.2"
    All PHP 4.x users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-lang/php-4.4.2"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200603-22] PHP: Format string and XSS vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'PHP: Format string and XSS vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "dev-lang/php", unaffected: make_list("ge 5.1.2"), vulnerable: make_list("lt 4.4.2", "rge 5.1.1", "rge 5.0.5", "rge 5.0.4")
)) { security_warning(0); exit(0); }
