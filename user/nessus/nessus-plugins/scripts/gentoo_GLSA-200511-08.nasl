# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200511-08.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(20195);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200511-08");
 script_cve_id("CVE-2005-3054", "CVE-2005-3319", "CVE-2005-3388", "CVE-2005-3389", "CVE-2005-3390", "CVE-2005-3391", "CVE-2005-3392");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200511-08
(PHP: Multiple vulnerabilities)


    Multiple vulnerabilities have been found and fixed in PHP:
    a possible $GLOBALS variable overwrite problem through file
    upload handling, extract() and import_request_variables()
    (CVE-2005-3390)
    a local Denial of Service through the use of
    the session.save_path option (CVE-2005-3319)
    an issue with
    trailing slashes in allowed basedirs (CVE-2005-3054)
    an issue
    with calling virtual() on Apache 2, allowing to bypass safe_mode and
    open_basedir restrictions (CVE-2005-3392)
    a problem when a
    request was terminated due to memory_limit constraints during certain
    parse_str() calls (CVE-2005-3389)
    The curl and gd modules
    allowed to bypass the safe mode open_basedir restrictions
    (CVE-2005-3391)
    a cross-site scripting (XSS) vulnerability in
    phpinfo() (CVE-2005-3388)
  
Impact

    Attackers could leverage these issues to exploit applications that
    are assumed to be secure through the use of proper register_globals,
    safe_mode or open_basedir parameters. Remote attackers could also
    conduct cross-site scripting attacks if a page calling phpinfo() was
    available. Finally, a local attacker could cause a local Denial of
    Service using malicious session.save_path options.
  
Workaround

    There is no known workaround that would solve all issues at this
    time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3054
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3319
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3388
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3389
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3390
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3391
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3392


Solution: 
    All PHP users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose dev-php/php
    All mod_php users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose dev-php/mod_php
    All php-cgi users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose dev-php/php-cgi
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200511-08] PHP: Multiple vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'PHP: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "dev-php/php-cgi", unaffected: make_list("rge 4.3.11-r5", "ge 4.4.0-r5"), vulnerable: make_list("lt 4.4.0-r5")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "dev-php/php", unaffected: make_list("rge 4.3.11-r4", "ge 4.4.0-r4"), vulnerable: make_list("lt 4.4.0-r4")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "dev-php/mod_php", unaffected: make_list("rge 4.3.11-r4", "ge 4.4.0-r8"), vulnerable: make_list("lt 4.4.0-r8")
)) { security_warning(0); exit(0); }
