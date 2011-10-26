# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200406-22.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14533);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200406-22");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200406-22
(Pavuk: Remote buffer overflow)


    When Pavuk connects to a web server and the server sends back the HTTP
    status code 305 (Use Proxy), Pavuk copies data from the HTTP Location
    header in an unsafe manner.  This bug was discovered by Ulf Harnhammar
    of the Debian Security Audit Project.
  
Impact

    An attacker could cause a stack-based buffer overflow which could lead to
    arbitrary code execution with the rights of the user running Pavuk.
  
Workaround

    There is no known workaround at this time. All users are encouraged to
    upgrade to the latest available version.
  

Solution: 
    All Pavuk users should upgrade to the latest stable version:
    # emerge sync
    # emerge -pv ">=net-misc/pavuk-0.9.28-r2"
    # emerge ">="net-misc/pavuk-0.9.28-r2
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200406-22] Pavuk: Remote buffer overflow");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Pavuk: Remote buffer overflow');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-misc/pavuk", unaffected: make_list("ge 0.9.28-r2"), vulnerable: make_list("le 0.9.28-r1")
)) { security_hole(0); exit(0); }
