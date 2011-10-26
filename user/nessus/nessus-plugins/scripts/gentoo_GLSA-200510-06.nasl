# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200510-06.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(19976);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200510-06");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200510-06
(Dia: Arbitrary code execution through SVG import)


    Joxean Koret discovered that the SVG import plugin in Dia fails to
    properly sanitise data read from an SVG file.
  
Impact

    An attacker could create a specially crafted SVG file, which, when
    imported into Dia, could lead to the execution of arbitrary code.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-2966


Solution: 
    All Dia users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-office/dia-0.94-r3"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200510-06] Dia: Arbitrary code execution through SVG import");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Dia: Arbitrary code execution through SVG import');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "app-office/dia", unaffected: make_list("ge 0.94-r3"), vulnerable: make_list("lt 0.94-r3")
)) { security_warning(0); exit(0); }
