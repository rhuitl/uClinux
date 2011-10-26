# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200410-12.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(15473);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200410-12");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200410-12
(WordPress: HTTP response splitting and XSS vulnerabilities)


    Due to the lack of input validation in the administration panel
    scripts, WordPress is vulnerable to HTTP response splitting and
    cross-site scripting attacks.
  
Impact

    A malicious user could inject arbitrary response data, leading to
    content spoofing, web cache poisoning and other cross-site scripting or
    HTTP response splitting attacks. This could result in compromising the
    victim\'s data or browser.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://wordpress.org/development/2004/12/one-point-two-two/


Solution: 
    All WordPress users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-apps/wordpress-1.2.2"
  

Risk factor : Low
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200410-12] WordPress: HTTP response splitting and XSS vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'WordPress: HTTP response splitting and XSS vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "www-apps/wordpress", unaffected: make_list("ge 1.2.2"), vulnerable: make_list("lt 1.2.2")
)) { security_warning(0); exit(0); }
