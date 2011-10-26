# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200403-02.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14453);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200403-02");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200403-02
(Linux kernel do_mremap local privilege escalation vulnerability)


    The memory subsystem allows for shrinking, growing, and moving of
    chunks of memory along any of the allocated memory areas which the
    kernel posesses.
    To accomplish this, the do_mremap code calls the do_munmap() kernel
    function to remove any old memory mappings in the new location - but,
    the code doesn\'t check the return value of the do_munmap() function
    which may fail if the maximum number of available virtual memory area
    descriptors has been exceeded.
    Due to the missing return value check after trying to unmap the middle
    of the first memory area, the corresponding page table entries from the
    second new area are inserted into the page table locations described by
    the first old one, thus they are subject to page protection flags of
    the first area. As a result, arbitrary code can be executed.
  
Impact

    Arbitrary code with normal non-super-user privelerges may be able to
    exploit this vulnerability and may disrupt the operation of other parts
    of the kernel memory management subroutines finally leading to
    unexpected behavior.
    Since no special privileges are required to use the mremap() and
    mummap() system calls any process may misuse this unexpected behavior
    to disrupt the kernel memory management subsystem. Proper exploitation
    of this vulnerability may lead to local privilege escalation allowing
    for the execution of arbitrary code with kernel level root access.
    Proof-of-concept exploit code has been created and successfully tested,
    permitting root escalation on vulnerable systems. As a result, all
    users should upgrade their kernels to new or patched versions.
  
Workaround

    Users who are unable to upgrade their kernels may attempt to use
    "sysctl -w vm.max_map_count=1000000", however, this is a temporary fix
    which only solves the problem by increasing the number of memory areas
    that can be created by each process. Because of the static nature of
    this workaround, it is not recommended and users are urged to upgrade
    their systems to the latest avaiable patched sources.
  
References:
    http://isec.pl/vulnerabilities/isec-0014-mremap-unmap.txt


Solution: 
    Users are encouraged to upgrade to the latest available sources for
    their system:
    # emerge sync
    # emerge -pv your-favourite-sources
    # emerge your-favourite-sources
    # # Follow usual procedure for compiling and installing a kernel.
    # # If you use genkernel, run genkernel as you would do normally.
    # # IF YOUR KERNEL IS MARKED as "remerge required!" THEN
    # # YOU SHOULD UPDATE YOUR KERNEL EVEN IF PORTAGE
    # # REPORTS THAT THE SAME VERSION IS INSTALLED.
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200403-02] Linux kernel do_mremap local privilege escalation vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Linux kernel do_mremap local privilege escalation vulnerability');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "sys-kernel/mips-prepatch-sources", unaffected: make_list("ge 2.4.25_pre6-r1"), vulnerable: make_list("lt 2.4.25_pre6-r1")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "sys-kernel/wolk-sources", unaffected: make_list("eq 4.9-r4", "ge 4.10_pre7-r3"), vulnerable: make_list("lt 4.10_pre7-r3")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "sys-kernel/hppa-sources", unaffected: make_list("ge 2.4.24_p0-r1"), vulnerable: make_list("lt 2.4.24_p0-r1")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "sys-kernel/vanilla-sources", unaffected: make_list("ge 2.4.25"), vulnerable: make_list("lt 2.4.25")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "sys-kernel/openmosix-sources", unaffected: make_list("ge 2.4.22-r4"), vulnerable: make_list("lt 2.4.22-r4")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "sys-kernel/grsec-sources", unaffected: make_list("ge 2.4.24.1.9.13-r1"), vulnerable: make_list("lt 2.4.24.1.9.13-r1")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "sys-kernel/hardened-sources", unaffected: make_list("ge 2.4.24-r1"), vulnerable: make_list("lt 2.4.24-r1")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "sys-kernel/ppc-sources-benh", unaffected: make_list("ge 2.4.22-r5"), vulnerable: make_list("lt 2.4.22-r5")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "sys-kernel/win4lin-sources", unaffected: make_list("eq 2.4.23-r2", "ge 2.6.2-r1"), vulnerable: make_list("lt 2.6.2-r1")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "sys-kernel/compaq-sources", unaffected: make_list("ge 2.4.9.32.7-r2"), vulnerable: make_list("lt 2.4.9.32.7-r2")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "sys-kernel/hppa-dev-sources", unaffected: make_list("ge 2.6.2_p3-r1"), vulnerable: make_list("lt 2.6.2_p3-r1")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "sys-kernel/sparc-sources", unaffected: make_list("ge 2.4.24-r2"), vulnerable: make_list("lt 2.4.24-r2")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "sys-kernel/ia64-sources", unaffected: make_list("ge 2.4.24-r1"), vulnerable: make_list("lt 2.4.24-r1")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "sys-kernel/gentoo-sources", unaffected: make_list("eq 2.4.19-r11", "eq 2.4.20-r12", "ge 2.4.22-r7"), vulnerable: make_list("lt 2.4.22-r7")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "sys-kernel/gs-sources", unaffected: make_list("ge 2.4.25_pre7-r2"), vulnerable: make_list("lt 2.4.25_pre7-r2")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "sys-kernel/gentoo-dev-sources", unaffected: make_list("ge 2.6.3_rc1"), vulnerable: make_list("lt 2.6.3_rc1")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "sys-kernel/usermode-sources", unaffected: make_list("rge 2.4.24-r1", "rge 2.4.26", "ge 2.6.3-r1"), vulnerable: make_list("lt 2.6.3-r1")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "sys-kernel/mips-sources", unaffected: make_list("ge 2.4.25_rc4"), vulnerable: make_list("lt 2.4.25_rc4")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "sys-kernel/vanilla-prepatch-sources", unaffected: make_list("ge 2.4.25_rc4"), vulnerable: make_list("lt 2.4.25_rc4")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "sys-kernel/ck-sources", unaffected: make_list("eq 2.4.24-r1", "ge 2.6.2-r1"), vulnerable: make_list("lt 2.6.2-r1")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "sys-kernel/pac-sources", unaffected: make_list("ge 2.4.23-r3"), vulnerable: make_list("lt 2.4.23-r3")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "sys-kernel/alpha-sources", unaffected: make_list("ge 2.4.21-r4"), vulnerable: make_list("lt 2.4.21-r4")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "sys-kernel/ppc-sources-crypto", unaffected: make_list("ge 2.4.20-r3"), vulnerable: make_list("lt 2.4.20-r3")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "sys-kernel/planet-ccrma-sources", unaffected: make_list("ge 2.4.21-r5"), vulnerable: make_list("lt 2.4.21-r5")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "sys-kernel/ppc-sources-dev", unaffected: make_list("ge 2.4.24-r2"), vulnerable: make_list("lt 2.4.24-r2")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "sys-kernel/ppc-sources", unaffected: make_list("ge 2.4.24-r1"), vulnerable: make_list("lt 2.4.24-r1")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "sys-kernel/gaming-sources", unaffected: make_list("ge 2.4.20-r8"), vulnerable: make_list("lt 2.4.20-r8")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "sys-kernel/xfs-sources", unaffected: make_list("ge 2.4.24-r2"), vulnerable: make_list("lt 2.4.24-r2")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "sys-kernel/selinux-sources", unaffected: make_list("ge 2.4.24-r2"), vulnerable: make_list("lt 2.4.24-r2")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "sys-kernel/ppc-development-sources", unaffected: make_list("ge 2.6.3_rc1-r1"), vulnerable: make_list("lt 2.6.3_rc1-r1")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "sys-kernel/development-sources", unaffected: make_list("ge 2.6.3_rc1"), vulnerable: make_list("lt 2.6.3_rc1")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "sys-kernel/sparc-dev-sources", unaffected: make_list("ge 2.6.3_rc1"), vulnerable: make_list("lt 2.6.3_rc1")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "sys-kernel/aa-sources", unaffected: make_list("ge 2.4.23-r1"), vulnerable: make_list("lt 2.4.23-r1")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "sys-kernel/mm-sources", unaffected: make_list("ge 2.6.3_rc1-r1"), vulnerable: make_list("lt 2.6.3_rc1-r1")
)) { security_hole(0); exit(0); }
