# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200408-24.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14580);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200408-24");
 script_cve_id("CVE-2004-0415", "CVE-2004-0685");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200408-24
(Linux Kernel: Multiple information leaks)


    The Linux kernel allows a local attacker to obtain sensitive kernel
    information by gaining access to kernel memory via several leaks in the
    /proc interfaces. These vulnerabilities exist in various drivers which make
    up a working Linux kernel, some of which are present across all
    architectures and configurations.
    CVE-2004-0415 deals with addressing invalid 32 to 64 bit conversions in the
    kernel, as well as insecure direct access to file offset pointers in kernel
    code which can be modified by the open(...), lseek(...) and other core
    system I/O functions by an attacker.
    CVE-2004-0685 deals with certain USB drivers using uninitialized structures
    and then using the copy_to_user(...) kernel call to copy these structures.
    This may leak uninitialized kernel memory, which can contain sensitive
    information from user applications.
    Finally, a race condition with the /proc/.../cmdline node was found,
    allowing environment variables to be read while the process was still
    spawning. If the race is won, environment variables of the process, which
    might not be owned by the attacker, can be read.
  
Impact

    These vulnerabilities allow a local unprivileged attacker to access
    segments of kernel memory or environment variables which may contain
    sensitive information. Kernel memory may contain passwords, data
    transferred between processes, any memory which applications did not
    clear upon exiting as well as the kernel cache and kernel buffers.
    This information may be used to read sensitive data, open other attack
    vectors for further exploitation or cause a Denial of Service if the
    attacker can gain superuser access via the leaked information.
  
Workaround

    There is no temporary workaround for any of these information leaks other
    than totally disabling /proc support - otherwise, a kernel upgrade is
    required. A list of unaffected kernels is provided along with this
    announcement.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0415
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0685


Solution: 
    Users are encouraged to upgrade to the latest available sources for their
    system:
    # emerge sync
    # emerge -pv your-favorite-sources
    # emerge your-favorite-sources
    # # Follow usual procedure for compiling and installing a kernel.
    # # If you use genkernel, run genkernel as you would normally.
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200408-24] Linux Kernel: Multiple information leaks");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Linux Kernel: Multiple information leaks');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "sys-kernel/sparc-sources", unaffected: make_list("ge 2.4.27-r1"), vulnerable: make_list("lt 2.4.27-r1")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "sys-kernel/uclinux-sources", unaffected: make_list("rge 2.4.26_p0-r6", "ge 2.6.7_p0-r5"), vulnerable: make_list("lt 2.6.7_p0-r5")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "sys-kernel/selinux-sources", unaffected: make_list("ge 2.4.26-r3"), vulnerable: make_list("lt 2.4.26-r3")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "sys-kernel/pegasos-dev-sources", unaffected: make_list("ge 2.6.8"), vulnerable: make_list("lt 2.6.8")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "sys-kernel/hppa-sources", unaffected: make_list("ge 2.4.26_p7-r1"), vulnerable: make_list("lt 2.4.26_p7-r1")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "sys-kernel/ck-sources", unaffected: make_list("rge 2.4.26-r1", "ge 2.6.7-r5"), vulnerable: make_list("lt 2.6.7-r5")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "sys-kernel/mm-sources", unaffected: make_list("ge 2.6.8_rc4-r1"), vulnerable: make_list("lt 2.6.8_rc4-r1")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "sys-kernel/xbox-sources", unaffected: make_list("rge 2.4.27-r1", "ge 2.6.7-r5"), vulnerable: make_list("lt 2.6.7-r5")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "sys-kernel/hardened-dev-sources", unaffected: make_list("ge 2.6.7-r7"), vulnerable: make_list("lt 2.6.7-r7")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "sys-kernel/wolk-sources", unaffected: make_list("rge 4.9-r14", "rge 4.11-r10", "ge 4.14-r7"), vulnerable: make_list("lt 4.14-r7")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "sys-kernel/development-sources", unaffected: make_list("ge 2.6.8"), vulnerable: make_list("lt 2.6.8")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "sys-kernel/grsec-sources", unaffected: make_list("ge 2.4.27.2.0.1-r1"), vulnerable: make_list("lt 2.4.27.2.0.1-r1")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "sys-kernel/alpha-sources", unaffected: make_list("ge 2.4.21-r12"), vulnerable: make_list("lt 2.4.21-r12")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "sys-kernel/ia64-sources", unaffected: make_list("ge 2.4.24-r10"), vulnerable: make_list("lt 2.4.24-r10")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "sys-kernel/gentoo-sources", unaffected: make_list("rge 2.4.19-r22", "rge 2.4.20-r25", "rge 2.4.22-r16", "rge 2.4.25-r9", "ge 2.4.26-r9"), vulnerable: make_list("lt 2.4.26-r9")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "sys-kernel/vserver-sources", unaffected: make_list("ge 2.4.26.1.28-r4"), vulnerable: make_list("lt 2.4.26.1.28-r4")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "sys-kernel/gentoo-dev-sources", unaffected: make_list("ge 2.6.7-r12"), vulnerable: make_list("lt 2.6.7-r12")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "sys-kernel/openmosix-sources", unaffected: make_list("ge 2.4.24-r4"), vulnerable: make_list("lt 2.4.24-r4")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "sys-kernel/aa-sources", unaffected: make_list("rge 2.4.23-r2", "ge 2.6.5-r5"), vulnerable: make_list("lt 2.6.5-r5")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "sys-kernel/pac-sources", unaffected: make_list("ge 2.4.23-r12"), vulnerable: make_list("lt 2.4.23-r12")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "sys-kernel/gs-sources", unaffected: make_list("ge 2.4.25_pre7-r11"), vulnerable: make_list("lt 2.4.25_pre7-r11")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "sys-kernel/hardened-sources", unaffected: make_list("ge 2.4.27-r1"), vulnerable: make_list("lt 2.4.27-r1")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "sys-kernel/win4lin-sources", unaffected: make_list("rge 2.4.26-r6", "ge 2.6.7-r2"), vulnerable: make_list("lt 2.6.7-r5")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "sys-kernel/vanilla-sources", unaffected: make_list("ge 2.4.27"), vulnerable: make_list("lt 2.4.27")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "sys-kernel/mips-sources", unaffected: make_list("rge 2.4.25-r8", "rge 2.4.26-r8", "rge 2.6.4-r8", "rge 2.6.6-r8", "ge 2.6.7-r5"), vulnerable: make_list("lt 2.6.6-r8")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "sys-kernel/rsbac-sources", unaffected: make_list("ge 2.4.26-r5"), vulnerable: make_list("lt 2.4.26-r5")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "sys-kernel/rsbac-dev-sources", unaffected: make_list("ge 2.6.7-r5"), vulnerable: make_list("lt 2.6.7-r5")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "sys-kernel/usermode-sources", unaffected: make_list("rge 2.4.24-r9", "rge 2.4.26-r6", "ge 2.6.6-r6"), vulnerable: make_list("lt 2.6.6-r6")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "sys-kernel/hppa-dev-sources", unaffected: make_list("ge 2.6.7_p14-r1"), vulnerable: make_list("lt 2.6.7_p14-r1")
)) { security_warning(0); exit(0); }
