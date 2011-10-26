# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200408-09.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14565);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200408-09");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200408-09
(Roundup: Filesystem access vulnerability)


    Improper handling of a specially crafted URL allows access to the server\'s
    filesystem, which could contain sensitive information.
  
Impact

    An attacker could view files owned by the user running Roundup. This will
    never be root however, as Roundup will not run as root.
  
Workaround

    There is no known workaround at this time. All users are encouraged to
    upgrade to the latest available version of Roundup.
  
References:
    http://secunia.com/advisories/11801/


Solution: 
    All Roundup users should upgrade to the latest version:
    # emerge sync
    # emerge -pv ">=net-www/roundup-0.7.6"
    # emerge ">=net-www/roundup-0.7.6"
  

Risk factor : Low
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200408-09] Roundup: Filesystem access vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Roundup: Filesystem access vulnerability');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-www/roundup", unaffected: make_list("ge 0.7.6"), vulnerable: make_list("le 0.6.4")
)) { security_warning(0); exit(0); }
