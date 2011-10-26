# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200504-15.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(18081);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200504-15");
 script_cve_id("CVE-2005-0524", "CVE-2005-0525", "CVE-2005-1042", "CVE-2005-1043");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200504-15
(PHP: Multiple vulnerabilities)


    An integer overflow and an unbound recursion were discovered in
    the processing of Image File Directory tags in PHP\'s EXIF module
    (CVE-2005-1042, CVE-2005-1043). Furthermore, two infinite loops have
    been discovered in the getimagesize() function when processing IFF or
    JPEG images (CVE-2005-0524, CVE-2005-0525).
  
Impact

    A remote attacker could craft an image file with a malicious EXIF
    IFD tag, a large IFD nesting level or invalid size parameters and send
    it to a web application that would process this user-provided image
    using one of the affected functions. This could result in denying
    service on the attacked server and potentially executing arbitrary code
    with the rights of the web server.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://www.php.net/release_4_3_11.php
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0524
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0525
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-1042
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-1043


Solution: 
    All PHP users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-php/php-4.3.11"
    All mod_php users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-php/mod_php-4.3.11"
    All php-cgi users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-php/php-cgi-4.3.11"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200504-15] PHP: Multiple vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'PHP: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "dev-php/php", unaffected: make_list("ge 4.3.11"), vulnerable: make_list("lt 4.3.11")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "dev-php/php-cgi", unaffected: make_list("ge 4.3.11"), vulnerable: make_list("lt 4.3.11")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "dev-php/mod_php", unaffected: make_list("ge 4.3.11"), vulnerable: make_list("lt 4.3.11")
)) { security_hole(0); exit(0); }
