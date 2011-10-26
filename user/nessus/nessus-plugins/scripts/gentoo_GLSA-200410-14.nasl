# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200410-14.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(15511);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200410-14");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200410-14
(phpMyAdmin: Vulnerability in MIME-based transformation system)


    A defect was found in phpMyAdmin\'s MIME-based transformation system, when
    used with "external" transformations.
  
Impact

    A remote attacker could exploit this vulnerability to execute arbitrary
    commands on the server with the rights of the HTTP server user.
  
Workaround

    Enabling PHP safe mode ("safe_mode = On" in php.ini) may serve as a
    temporary workaround.
  
References:
    http://sourceforge.net/forum/forum.php?forum_id=414281
    http://secunia.com/advisories/12813/


Solution: 
    All phpMyAdmin users should upgrade to the latest version:
    # emerge sync
    # emerge -pv ">=dev-db/phpmyadmin-2.6.0_p2"
    # emerge ">=dev-db/phpmyadmin-2.6.0_p2"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200410-14] phpMyAdmin: Vulnerability in MIME-based transformation system");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'phpMyAdmin: Vulnerability in MIME-based transformation system');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "dev-db/phpmyadmin", unaffected: make_list("ge 2.6.0_p2"), vulnerable: make_list("lt 2.6.0_p2")
)) { security_hole(0); exit(0); }
