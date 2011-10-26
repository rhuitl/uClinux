# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200405-02.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14488);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200405-02");
 script_cve_id("CVE-2004-0234", "CVE-2004-0235");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200405-02
(Multiple vulnerabilities in LHa)


    Ulf Harnhammar found two stack overflows and two directory traversal
    vulnerabilities in LHa version 1.14 and 1.17. A stack overflow occurs when
    testing or extracting archives containing long file or directory names.
    Furthermore, LHa doesn\'t contain sufficient protection against relative or
    absolute archive paths.
  
Impact

    The stack overflows can be exploited to execute arbitrary code with the
    rights of the user testing or extracting the archive. The directory
    traversal vulnerabilities can be used to overwrite files in the filesystem
    with the rights of the user extracting the archive, potentially leading to
    denial of service or privilege escalation. Since LHa is often interfaced to
    other software like an email virus scanner, this attack can be used
    remotely.
  
Workaround

    There is no known workaround at this time. All users are advised to upgrade
    to the latest available version of LHa.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0234
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0235


Solution: 
    All users of LHa should upgrade to the latest stable version:
    # emerge sync
    # emerge -pv ">=app-arch/lha-114i-r2"
    # emerge ">=app-arch/lha-114i-r2"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200405-02] Multiple vulnerabilities in LHa");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Multiple vulnerabilities in LHa');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "app-arch/lha", unaffected: make_list("ge 114i-r2"), vulnerable: make_list("le 114i-r1")
)) { security_hole(0); exit(0); }
