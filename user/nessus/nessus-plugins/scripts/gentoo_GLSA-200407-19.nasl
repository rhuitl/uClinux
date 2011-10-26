# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200407-19.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14552);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200407-19");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200407-19
(Pavuk: Digest authentication helper buffer overflow)


    Pavuk contains several buffer overflow vulnerabilities in the code handling
    digest authentication.
  
Impact

    An attacker could cause a buffer overflow, leading to arbitrary code
    execution with the rights of the user running Pavuk.
  
Workaround

    There is no known workaround at this time. All users are encouraged to
    upgrade to the latest available version of Pavuk.
  

Solution: 
    All Pavuk users should upgrade to the latest version:
    # emerge sync
    # emerge -pv ">=net-misc/pavuk-0.9.28-r3"
    # emerge ">=net-misc/pavuk-0.9.28-r3"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200407-19] Pavuk: Digest authentication helper buffer overflow");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Pavuk: Digest authentication helper buffer overflow');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-misc/pavuk", unaffected: make_list("ge 0.9.28-r3"), vulnerable: make_list("le 0.9.28-r2")
)) { security_warning(0); exit(0); }
