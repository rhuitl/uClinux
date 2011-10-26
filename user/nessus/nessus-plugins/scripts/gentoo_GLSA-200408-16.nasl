# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200408-16.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14572);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200408-16");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200408-16
(glibc: Information leak with LD_DEBUG)


    Silvio Cesare discovered a potential information leak in glibc. It allows
    LD_DEBUG on SUID binaries where it should not be allowed. This has various
    security implications, which may be used to gain confidentional
    information.
  
Impact

    An attacker can gain the list of symbols a SUID application uses and their
    locations and can then use a trojaned library taking precendence over those
    symbols to gain information or perform further exploitation.
  
Workaround

    There is no known workaround at this time. All users are encouraged to
    upgrade to the latest available version of glibc.
  

Solution: 
    All glibc users should upgrade to the latest version:
    # emerge sync
    # emerge -pv your_version
    # emerge your_version
  

Risk factor : Low
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200408-16] glibc: Information leak with LD_DEBUG");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'glibc: Information leak with LD_DEBUG');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "sys-libs/glibc", arch: "ppc64", unaffected: make_list("ge 2.3.4.20040808"), vulnerable: make_list("le 2.3.4.20040605")
)) { security_warning(0); exit(0); }
