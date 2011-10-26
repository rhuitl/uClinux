# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200506-01.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(18406);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200506-01");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200506-01
(Binutils, elfutils: Buffer overflow)


    Tavis Ormandy and Ned Ludd of the Gentoo Linux Security Audit Team
    discovered an integer overflow in the BFD library and elfutils,
    resulting in a heap based buffer overflow.
  
Impact

    Successful exploitation would require a user to access a specially
    crafted binary file, resulting in the execution of arbitrary code.
  
Workaround

    There is no known workaround at this time.
  

Solution: 
    All GNU Binutils users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose sys-devel/binutils
    All elfutils users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-libs/elfutils-0.108"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200506-01] Binutils, elfutils: Buffer overflow");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Binutils, elfutils: Buffer overflow');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "sys-devel/binutils", unaffected: make_list("rge 2.14.90.0.8-r3", "rge 2.15.90.0.1.1-r5", "rge 2.15.90.0.3-r5", "rge 2.15.91.0.2-r2", "rge 2.15.92.0.2-r10", "ge 2.16-r1"), vulnerable: make_list("lt 2.16-r1")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "dev-libs/elfutils", unaffected: make_list("ge 0.108"), vulnerable: make_list("lt 0.108")
)) { security_warning(0); exit(0); }
