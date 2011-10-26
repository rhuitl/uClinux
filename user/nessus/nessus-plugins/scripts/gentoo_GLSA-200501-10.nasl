# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200501-10.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(16401);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200501-10");
 script_cve_id("CVE-2004-1299");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200501-10
(Vilistextum: Buffer overflow vulnerability)


    Ariel Berkman discovered that Vilistextum unsafely reads data into
    an array without checking the length. This code vulnerability may lead
    to a buffer overflow.
  
Impact

    A remote attacker could craft a malicious webpage which, when
    converted, would result in the execution of arbitrary code with the
    rights of the user running Vilistextum.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://tigger.uic.edu/~jlongs2/holes/vilistextum.txt
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-1299


Solution: 
    All Vilistextum users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-text/vilistextum-2.6.7"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200501-10] Vilistextum: Buffer overflow vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Vilistextum: Buffer overflow vulnerability');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "app-text/vilistextum", unaffected: make_list("ge 2.6.7"), vulnerable: make_list("lt 2.6.7")
)) { security_warning(0); exit(0); }
