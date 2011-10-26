# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200603-05.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(21022);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200603-05");
 script_cve_id("CVE-2006-0855");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200603-05
(zoo: Stack-based buffer overflow)


    Jean-Sebastien Guay-Leroux discovered a boundary error in the
    fullpath() function in misc.c when processing overly long file and
    directory names in ZOO archives.
  
Impact

    An attacker could craft a malicious ZOO archive and entice someone
    to open it using zoo. This would trigger a stack-based buffer overflow
    and potentially allow execution of arbitrary code with the rights of
    the victim user.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-0855
    http://www.guay-leroux.com/projects/zoo-advisory.txt


Solution: 
    All zoo users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-arch/zoo-2.10-r1"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200603-05] zoo: Stack-based buffer overflow");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'zoo: Stack-based buffer overflow');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "app-arch/zoo", unaffected: make_list("ge 2.10-r1"), vulnerable: make_list("lt 2.10-r1")
)) { security_warning(0); exit(0); }
