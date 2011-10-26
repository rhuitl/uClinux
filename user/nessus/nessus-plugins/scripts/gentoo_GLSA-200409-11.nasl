# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200409-11.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14675);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200409-11");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200409-11
(star: Suid root vulnerability)


    A suid root vulnerability exists in versions of star that are configured to
    use ssh for remote tape access.
  
Impact

    Attackers with local user level access could potentially gain root level
    access.
  
Workaround

    There is no known workaround at this time.
  
References:
    https://lists.berlios.de/pipermail/star-users/2004-August/000239.html


Solution: 
    All star users should upgrade to the latest version:
    # emerge sync
    # emerge -pv ">=app-arch/star-1.5_alpha46"
    # emerge ">=app-arch/star-1.5_alpha46"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200409-11] star: Suid root vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'star: Suid root vulnerability');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "app-arch/star", unaffected: make_list("ge star-1.5_alpha46"), vulnerable: make_list("lt star-1.5_alpha46")
)) { security_hole(0); exit(0); }
