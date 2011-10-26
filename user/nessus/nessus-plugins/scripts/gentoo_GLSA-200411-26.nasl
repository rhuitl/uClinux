# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200411-26.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(15754);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200411-26");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200411-26
(GIMPS, SETI@home, ChessBrain: Insecure installation)


    GIMPS, SETI@home and ChessBrain ebuilds install user-owned binaries and
    init scripts which are executed with root privileges.
  
Impact

    This could lead to a local privilege escalation or root compromise.
  
Workaround

    There is no known workaround at this time.
  

Solution: 
    All GIMPS users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-sci/gimps-23.9-r1"
    All SETI@home users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-sci/setiathome-3.03-r2"
    All ChessBrain users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-sci/chessbrain-20407-r1"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200411-26] GIMPS, SETI@home, ChessBrain: Insecure installation");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'GIMPS, SETI@home, ChessBrain: Insecure installation');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "app-sci/gimps", unaffected: make_list("ge 23.9-r1"), vulnerable: make_list("le 23.9")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "app-sci/setiathome", unaffected: make_list("ge 3.08-r4", "rge 3.03-r2"), vulnerable: make_list("le 3.08-r3")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "app-sci/chessbrain", unaffected: make_list("ge 20407-r1"), vulnerable: make_list("le 20407")
)) { security_hole(0); exit(0); }
