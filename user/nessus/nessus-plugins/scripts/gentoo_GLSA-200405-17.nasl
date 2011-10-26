# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200405-17.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14503);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200405-17");
 script_cve_id("CVE-2004-0104", "CVE-2004-0105");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200405-17
(Multiple vulnerabilities in metamail)


    Ulf Harnhammar found two format string bugs and two buffer overflow bugs in
    Metamail.
  
Impact

    A remote attacker could send a malicious email message and execute
    arbitrary code with the rights of the process calling the Metamail program.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0104
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0105


Solution: 
    All users of Metamail should upgrade to the latest stable version:
    # emerge sync
    # emerge -pv ">=net-mail/metamail-2.7.45.3"
    # emerge ">=net-mail/metamail-2.7.45.3"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200405-17] Multiple vulnerabilities in metamail");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Multiple vulnerabilities in metamail');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-mail/metamail", unaffected: make_list("ge 2.7.45.3"), vulnerable: make_list("lt 2.7.45.3")
)) { security_hole(0); exit(0); }
