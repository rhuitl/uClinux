# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200401-01.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14441);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200401-01");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200401-01
(Linux kernel do_mremap() local privilege escalation vulnerability)


    The memory subsystem allows for shrinking, growing, and moving of
    chunks of memory along any of the allocated memory areas which the kernel
    posesses.
    A typical virtual memory area covers at least one memory page. An incorrect
    bound check discovered inside the do_mremap() kernel code performing
    remapping of a virtual memory area may lead to creation of a virtual memory
    area of 0 bytes length.
    The problem is based on the general mremap flaw that remapping 2 pages from
    inside a VMA creates a memory hole of only one page in length but an
    additional VMA of two pages. In the case of a zero sized remapping request
    no VMA hole is created but an additional VMA descriptor of 0
    bytes in length is created.
    This advisory also addresses an information leak in the Linux RTC system.
  
Impact

    Arbitrary code may be able to exploit this vulnerability and may
    disrupt the operation of other
    parts of the kernel memory management subroutines finally leading to
    unexpected behavior.
    Since no special privileges are required to use the mremap(2) system call
    any process may misuse its unexpected behavior to disrupt the kernel memory
    management subsystem. Proper exploitation of this vulnerability may lead to
    local privilege escalation including execution of arbitrary code
    with kernel level access.
    Proof-of-concept exploit code has been created and successfully tested,
    permitting root escalation on vulnerable systems. As a result, all users
    should upgrade their kernels to new or patched versions.
  
Workaround

    There is no temporary workaround - a kernel upgrade is required. A list
    of unaffected kernels is provided along with this announcement.
  
References:
    http://isec.pl/vulnerabilities/isec-0012-mremap.txt


Solution: 
    Users are encouraged to upgrade to the latest available sources for
    their system:
    $> emerge sync
    $> emerge -pv your-favourite-sources
    $> emerge your-favourite-sources
    $> # Follow usual procedure for compiling and installing a kernel.
    $> # If you use genkernel, run genkernel as you would do normally.
    $> # IF YOUR KERNEL IS MARKED as "remerge required!" THEN
    $> # YOU SHOULD UPDATE YOUR KERNEL EVEN IF PORTAGE
    $> # REPORTS THAT THE SAME VERSION IS INSTALLED.
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200401-01] Linux kernel do_mremap() local privilege escalation vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Linux kernel do_mremap() local privilege escalation vulnerability');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "sys-kernel/aa-sources", unaffected: make_list("ge 2.4.23-r1"), vulnerable: make_list("lt 2.4.23-r1")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "sys-kernel/mips-prepatch-sources", unaffected: make_list("ge 2.4.24_pre2-r1"), vulnerable: make_list("lt 2.4.24_pre2-r1")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "sys-kernel/gentoo-dev-sources", unaffected: make_list("ge 2.6.1_rc3"), vulnerable: make_list("lt 2.6.1_rc3")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "sys-kernel/gaming-sources", unaffected: make_list("ge 2.4.20-r7"), vulnerable: make_list("lt 2.4.20-r7")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "sys-kernel/ppc-development-sources", unaffected: make_list("ge 2.6.1_rc1-r1"), vulnerable: make_list("lt 2.6.1_rc1-r1")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "sys-kernel/arm-sources", unaffected: make_list("ge 2.4.19-r2"), vulnerable: make_list("lt 2.4.19-r2")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "sys-kernel/alpha-sources", unaffected: make_list("ge 2.4.21-r2"), vulnerable: make_list("lt 2.4.21-r2")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "sys-kernel/vanilla-prepatch-sources", unaffected: make_list("ge 2.4.25_pre4"), vulnerable: make_list("lt 2.4.25_pre4")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "sys-kernel/win4lin-sources", unaffected: make_list("ge 2.6.0-r1"), vulnerable: make_list("lt 2.6.0-r1")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "sys-kernel/vanilla-sources", unaffected: make_list("ge 2.4.24"), vulnerable: make_list("lt 2.4.24")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "sys-kernel/hppa-sources", unaffected: make_list("ge 2.4.23_p4-r2"), vulnerable: make_list("lt 2.4.23_p4-r2")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "sys-kernel/development-sources", unaffected: make_list("ge 2.6.1_rc3"), vulnerable: make_list("lt 2.6.1_rc3")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "sys-kernel/grsec-sources", unaffected: make_list("gt 2.4.23.2.0_rc4-r1"), vulnerable: make_list("lt 2.4.23.2.0_rc4-r1")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "sys-kernel/compaq-sources", unaffected: make_list("ge 2.4.9.32.7-r1"), vulnerable: make_list("lt 2.4.9.32.7-r1")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "sys-kernel/hardened-sources", unaffected: make_list("ge 2.4.22-r2"), vulnerable: make_list("lt 2.4.22-r2")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "sys-kernel/sparc-sources", unaffected: make_list("ge 2.4.24"), vulnerable: make_list("lt 2.4.24")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "sys-kernel/openmosix-sources", unaffected: make_list("ge 2.4.22-r3"), vulnerable: make_list("lt 2.4.22-r3")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "sys-kernel/ppc-sources-benh", unaffected: make_list("ge 2.4.22-r4"), vulnerable: make_list("lt 2.4.22-r4")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "sys-kernel/ppc-sources-crypto", unaffected: make_list("ge 2.4.20-r2"), vulnerable: make_list("lt 2.4.20-r2")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "sys-kernel/mm-sources", unaffected: make_list("ge 2.6.1_rc1-r2"), vulnerable: make_list("lt 2.6.1_rc1-r2")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "sys-kernel/xfs-sources", unaffected: make_list("ge 2.4.23-r1"), vulnerable: make_list("lt 2.4.23-r1")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "sys-kernel/ia64-sources", unaffected: make_list("ge 2.4.22-r2"), vulnerable: make_list("lt 2.4.22-r2")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "sys-kernel/pfeifer-sources", unaffected: make_list("ge 2.4.21.1_pre4-r1"), vulnerable: make_list("lt 2.4.21.1_pre4-r1")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "sys-kernel/planet-ccrma-sources", unaffected: make_list("ge 2.4.21-r4"), vulnerable: make_list("lt 2.4.21-r4")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "sys-kernel/ck-sources", unaffected: make_list("ge 2.4.23-r1"), vulnerable: make_list("lt 2.4.23-r1")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "sys-kernel/usermode-sources", unaffected: make_list("ge 2.4.23-r1"), vulnerable: make_list("lt 2.4.23-r1")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "sys-kernel/gentoo-sources", unaffected: make_list("gt 2.4.22-r3"), vulnerable: make_list("lt 2.4.22-r3")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "sys-kernel/selinux-sources", unaffected: make_list("ge 2.4.24"), vulnerable: make_list("lt 2.4.24")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "sys-kernel/ppc-sources", unaffected: make_list("ge 2.4.23-r1"), vulnerable: make_list("lt 2.4.23-r1")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "sys-kernel/gs-sources", unaffected: make_list("ge 2.4.23_pre8-r2"), vulnerable: make_list("lt 2.4.23_pre8-r2")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "sys-kernel/pac-sources", unaffected: make_list("ge 2.4.23-r1"), vulnerable: make_list("lt 2.4.23-r1")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "sys-kernel/wolk-sources", unaffected: make_list("ge 4.10_pre7-r2"), vulnerable: make_list("lt 4.10_pre7-r2")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "sys-kernel/mips-sources", unaffected: make_list("ge 2.4.23-r2"), vulnerable: make_list("lt 2.4.23-r2")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "sys-kernel/sparc-dev-sources", unaffected: make_list("ge 2.6.1_rc2"), vulnerable: make_list("lt 2.6.1_rc2")
)) { security_hole(0); exit(0); }
