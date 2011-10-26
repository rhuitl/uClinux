# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200409-13.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14694);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200409-13");
 script_cve_id("CVE-2004-0694", "CVE-2004-0745", "CVE-2004-0769", "CVE-2004-0771");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200409-13
(LHa: Multiple vulnerabilities)


    The command line argument as well as the archive parsing code of LHa lack
    sufficient bounds checking. Furthermore, a shell meta character command
    execution vulnerability exists in LHa, since it does no proper filtering on
    directory names.
  
Impact

    Using a specially crafted command line argument or archive, an attacker can
    cause a buffer overflow and could possibly run arbitrary code. The shell
    meta character command execution could lead to the execution of arbitrary
    commands by an attacker using directories containing shell meta characters
    in their names.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0694
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0745
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0769
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0771


Solution: 
    All LHa users should upgrade to the latest stable version:
    # emerge sync
    # emerge -pv ">=app-arch/lha-114i-r4"
    # emerge ">=app-arch/lha-114i-r4"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200409-13] LHa: Multiple vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'LHa: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "app-arch/lha", unaffected: make_list("ge 114i-r4"), vulnerable: make_list("le 114i-r3")
)) { security_warning(0); exit(0); }
