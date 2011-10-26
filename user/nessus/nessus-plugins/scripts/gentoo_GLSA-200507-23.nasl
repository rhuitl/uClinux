# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200507-23.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(19325);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200507-23");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200507-23
(Kopete: Vulnerability in included Gadu library)


    Kopete contains an internal copy of libgadu and is therefore
    subject to several input validation vulnerabilities in libgadu.
  
Impact

    A remote attacker could exploit this vulnerability to execute
    arbitrary code or crash Kopete.
  
Workaround

    Delete all Gadu Gadu contacts.
  
References:
    http://www.kde.org/info/security/advisory-20050721-1.txt
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-1852


Solution: 
    All Kopete users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose kde-base/kdenetwork
    All KDE Split Ebuild Kopete users should upgrade to the latest
    version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=kde-base/kopete-3.4.1-r1"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200507-23] Kopete: Vulnerability in included Gadu library");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Kopete: Vulnerability in included Gadu library');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "kde-base/kdenetwork", unaffected: make_list("ge 3.4.1-r1", "rge 3.3.2-r2"), vulnerable: make_list("lt 3.4.1-r1")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "kde-base/kopete", unaffected: make_list("ge 3.4.1-r1"), vulnerable: make_list("lt 3.4.1-r1")
)) { security_hole(0); exit(0); }
