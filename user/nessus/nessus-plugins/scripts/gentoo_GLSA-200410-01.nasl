# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200410-01.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(15407);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200410-01");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200410-01
(sharutils: Buffer overflows in shar.c and unshar.c)


    sharutils contains two buffer overflows. Ulf Harnhammar discovered a buffer
    overflow in shar.c, where the length of data returned by the wc command is
    not checked. Florian Schilhabel discovered another buffer overflow in
    unshar.c.
  
Impact

    An attacker could exploit these vulnerabilities to execute arbitrary code
    as the user running one of the sharutils programs.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=265904


Solution: 
    All sharutils users should upgrade to the latest version:
    # emerge sync
    # emerge -pv ">=app-arch/sharutils-4.2.1-r10"
    # emerge ">=app-arch/sharutils-4.2.1-r10"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200410-01] sharutils: Buffer overflows in shar.c and unshar.c");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'sharutils: Buffer overflows in shar.c and unshar.c');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "app-arch/sharutils", unaffected: make_list("ge 4.2.1-r10"), vulnerable: make_list("le 4.2.1-r9")
)) { security_warning(0); exit(0); }
