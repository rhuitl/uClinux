# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200412-14.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(16001);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200412-14");
 script_cve_id("CVE-2004-1019", "CVE-2004-1065");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200412-14
(PHP: Multiple vulnerabilities)


    Stefan Esser and Marcus Boerger reported several different issues
    in the unserialize() function, including serious exploitable bugs in
    the way it handles negative references (CVE-2004-1019).
    Stefan
    Esser also discovered that the pack() and unpack() functions are
    subject to integer overflows that can lead to a heap buffer overflow
    and a heap information leak. Finally, he found that the way
    multithreaded PHP handles safe_mode_exec_dir restrictions can be
    bypassed, and that various path truncation issues also allow to bypass
    path and safe_mode restrictions.
    Ilia Alshanetsky found a
    stack overflow issue in the exif_read_data() function (CVE-2004-1065).
    Finally, Daniel Fabian found that addslashes and magic_quotes_gpc do
    not properly escape null characters and that magic_quotes_gpc contains
    a bug that could lead to one level directory traversal.
  
Impact

    These issues could be exploited by a remote attacker to retrieve
    web server heap information, bypass safe_mode or path restrictions and
    potentially execute arbitrary code with the rights of the web server
    running a PHP application.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://www.php.net/release_4_3_10.php
    http://www.hardened-php.net/advisories/012004.txt
    http://www.securityfocus.com/archive/1/384663/2004-12-15/2004-12-21/0
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-1019
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-1065


Solution: 
    All PHP users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-php/php-4.3.10"
    All mod_php users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-php/mod_php-4.3.10"
    All php-cgi users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-php/php-cgi-4.3.10"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200412-14] PHP: Multiple vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'PHP: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "dev-php/mod_php", unaffected: make_list("ge 4.3.10"), vulnerable: make_list("lt 4.3.10")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "dev-php/php", unaffected: make_list("ge 4.3.10"), vulnerable: make_list("lt 4.3.10")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "dev-php/php-cgi", unaffected: make_list("ge 4.3.10"), vulnerable: make_list("lt 4.3.10")
)) { security_hole(0); exit(0); }
