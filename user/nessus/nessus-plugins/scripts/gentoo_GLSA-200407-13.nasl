# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200407-13.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14546);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200407-13");
 script_cve_id("CVE-2004-0594", "CVE-2004-0595");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200407-13
(PHP: Multiple security vulnerabilities)


    Several security vulnerabilities were found and fixed in version 4.3.8 of
    PHP. The strip_tags() function, used to sanitize user input, could in
    certain cases allow tags containing \\0 characters (CVE-2004-0595). When
    memory_limit is used, PHP might unsafely interrupt other functions
    (CVE-2004-0594). The ftok and itpc functions were missing safe_mode checks.
    It was possible to bypass open_basedir restrictions using MySQL\'s LOAD DATA
    LOCAL function. Furthermore, the IMAP extension was incorrectly allocating
    memory and alloca() calls were replaced with emalloc() for better stack
    protection.
  
Impact

    Successfully exploited, the memory_limit problem could allow remote
    excution of arbitrary code. By exploiting the strip_tags vulnerability, it
    is possible to pass HTML code that would be considered as valid tags by the
    Microsoft Internet Explorer and Safari browsers. Using ftok, itpc or
    MySQL\'s LOAD DATA LOCAL, it is possible to bypass PHP configuration
    restrictions.
  
Workaround

    There is no known workaround that would solve all these problems. All users
    are encouraged to upgrade to the latest available versions.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0594
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0595
    http://security.e-matters.de/advisories/112004.html
    http://security.e-matters.de/advisories/122004.html


Solution: 
    All PHP, mod_php and php-cgi users should upgrade to the latest stable
    version:
    # emerge sync
    # emerge -pv ">=dev-php/php-4.3.8"
    # emerge ">=dev-php/php-4.3.8"
    # emerge -pv ">=dev-php/mod_php-4.3.8"
    # emerge ">=dev-php/mod_php-4.3.8"
    # emerge -pv ">=dev-php/php-cgi-4.3.8"
    # emerge ">=dev-php/php-cgi-4.3.8"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200407-13] PHP: Multiple security vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'PHP: Multiple security vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "dev-php/php", unaffected: make_list("ge 4.3.8"), vulnerable: make_list("le 4.3.7-r1")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "dev-php/mod_php", unaffected: make_list("ge 4.3.8"), vulnerable: make_list("le 4.3.7-r1")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "dev-php/php-cgi", unaffected: make_list("ge 4.3.8"), vulnerable: make_list("le 4.3.7-r1")
)) { security_hole(0); exit(0); }
