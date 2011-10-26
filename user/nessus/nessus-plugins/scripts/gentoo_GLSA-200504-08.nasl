# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200504-08.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(18013);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200504-08");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200504-08
(phpMyAdmin: Cross-site scripting vulnerability)


    Oriol Torrent Santiago has discovered that phpMyAdmin fails to
    validate input to the "convcharset" variable, rendering it vulnerable
    to cross-site scripting attacks.
  
Impact

    By sending a specially-crafted request, an attacker can inject and
    execute malicious script code, potentially compromising the victim\'s
    browser.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://www.phpmyadmin.net/home_page/security.php?issue=PMASA-2005-3


Solution: 
    All phpMyAdmin users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-db/phpmyadmin-2.6.2_rc1"
  

Risk factor : Low
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200504-08] phpMyAdmin: Cross-site scripting vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'phpMyAdmin: Cross-site scripting vulnerability');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "dev-db/phpmyadmin", unaffected: make_list("ge 2.6.2_rc1"), vulnerable: make_list("lt 2.6.2_rc1")
)) { security_warning(0); exit(0); }
