# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200509-03.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(19578);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200509-03");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200509-03
(OpenTTD: Format string vulnerabilities)


    Alexey Dobriyan discovered several format string vulnerabilities
    in OpenTTD.
  
Impact

    A remote attacker could exploit these vulnerabilities to crash the
    OpenTTD server or client and possibly execute arbitrary code with the
    rights of the user running OpenTTD.
  
Workaround

    There are no known workarounds at this time.
  
References:
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-2763


Solution: 
    All OpenTTD users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=games-simulation/openttd-0.4.0.1-r1"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200509-03] OpenTTD: Format string vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'OpenTTD: Format string vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "games-simulation/openttd", unaffected: make_list("ge 0.4.0.1-r1"), vulnerable: make_list("lt 0.4.0.1-r1")
)) { security_hole(0); exit(0); }
