# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200511-18.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(20262);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200511-18");
 script_cve_id("CVE-2005-3347", "CVE-2005-3348");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200511-18
(phpSysInfo: Multiple vulnerabilities)


    Christopher Kunz from the Hardened-PHP Project discovered
    that phpSysInfo is vulnerable to local file inclusion, cross-site
    scripting and a HTTP Response Splitting attacks.
  
Impact

    A local attacker may exploit the file inclusion vulnerability by
    sending malicious requests, causing the execution of arbitrary code
    with the rights of the user running the web server. A remote attacker
    could exploit the vulnerability to disclose local file content.
    Furthermore, the cross-site scripting issues gives a remote attacker
    the ability to inject and execute malicious script code in the user\'s
    browser context or to steal cookie-based authentication credentials.
    The HTTP response splitting issue give an attacker the ability to
    perform site hijacking and cache poisoning.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://www.hardened-php.net/advisory_222005.81.html
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3347
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3348


Solution: 
    All phpSysInfo users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-apps/phpsysinfo-2.4.1"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200511-18] phpSysInfo: Multiple vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'phpSysInfo: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "www-apps/phpsysinfo", unaffected: make_list("ge 2.4.1"), vulnerable: make_list("lt 2.4.1")
)) { security_warning(0); exit(0); }
