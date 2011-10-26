# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200606-03.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(21665);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200606-03");
 script_cve_id("CVE-2006-2453", "CVE-2006-2480");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200606-03
(Dia: Format string vulnerabilities)


    KaDaL-X discovered a format string error within the handling of
    filenames. Hans de Goede also discovered several other format
    string errors in the processing of dia files.
  
Impact

    By enticing a user to open a specially crafted file, a remote
    attacker could exploit these vulnerabilities to execute arbitrary code
    with the rights of the user running the application.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-2453
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-2480


Solution: 
    All Dia users should upgrade to the latest available version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-office/dia-0.95.1"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200606-03] Dia: Format string vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Dia: Format string vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "app-office/dia", unaffected: make_list("ge 0.95.1"), vulnerable: make_list("lt 0.95.1")
)) { security_warning(0); exit(0); }
