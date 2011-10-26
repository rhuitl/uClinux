# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200512-03.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(20312);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200512-03");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200512-03
(phpMyAdmin: Multiple vulnerabilities)


    Stefan Esser from Hardened-PHP reported about multiple
    vulnerabilties found in phpMyAdmin. The $GLOBALS variable allows
    modifying the global variable import_blacklist to open phpMyAdmin to
    local and remote file inclusion, depending on your PHP version
    (CVE-2005-4079, PMASA-2005-9). Furthermore, it is also possible to
    conduct an XSS attack via the $HTTP_HOST variable and a local and
    remote file inclusion because the contents of the variable are under
    total control of the attacker (CVE-2005-3665, PMASA-2005-8).
  
Impact

    A remote attacker may exploit these vulnerabilities by sending
    malicious requests, causing the execution of arbitrary code with the
    rights of the user running the web server. The cross-site scripting
    issues allow a remote attacker to inject and execute malicious script
    code or to steal cookie-based authentication credentials, potentially
    allowing unauthorized access to phpMyAdmin.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3665
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-4079
    http://www.phpmyadmin.net/home_page/security.php?issue=PMASA-2005-8
    http://www.phpmyadmin.net/home_page/security.php?issue=PMASA-2005-9
    http://www.hardened-php.net/advisory_252005.110.html


Solution: 
    All phpMyAdmin users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-db/phpmyadmin-2.7.0_p1"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200512-03] phpMyAdmin: Multiple vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'phpMyAdmin: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "dev-db/phpmyadmin", unaffected: make_list("ge 2.7.0_p1"), vulnerable: make_list("lt 2.7.0_p1")
)) { security_warning(0); exit(0); }
