# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200407-12.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14545);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200407-12");
 script_cve_id("CVE-2004-0626");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200407-12
(Linux Kernel: Remote DoS vulnerability with IPTables TCP Handling)


    An attacker can utilize an erroneous data type in the IPTables TCP option
    handling code, which lies in an iterator. By making a TCP packet with a
    header length larger than 127 bytes, a negative integer would be implied in
    the iterator.
  
Impact

    By sending one malformed packet, the kernel could get stuck in a loop,
    consuming all of the CPU resources and rendering the machine useless,
    causing a Denial of Service. This vulnerability requires no local access.
  
Workaround

    If users do not use the netfilter functionality or do not use any
    ``--tcp-option\'\' rules they are not vulnerable to this exploit. Users that
    are may remove netfilter support from their kernel or may remove any
    ``--tcp-option\'\' rules they might be using. However, all users are urged to
    upgrade their kernels to patched versions.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0626


Solution: 
    Users are encouraged to upgrade to the latest available sources for their
    system:
    # emerge sync
    # emerge -pv your-favorite-sources
    # emerge your-favorite-sources
    # # Follow usual procedure for compiling and installing a kernel.
    # # If you use genkernel, run genkernel as you would do normally.
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200407-12] Linux Kernel: Remote DoS vulnerability with IPTables TCP Handling");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Linux Kernel: Remote DoS vulnerability with IPTables TCP Handling');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "sys-kernel/win4lin-sources", unaffected: make_list("ge 2.6.7-r1", "lt 2.6"), vulnerable: make_list("lt 2.6.7-r1")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "sys-kernel/rsbac-dev-sources", unaffected: make_list("ge 2.6.7-r1"), vulnerable: make_list("lt 2.6.7-r1")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "sys-kernel/xbox-sources", unaffected: make_list("ge 2.6.7-r1", "lt 2.6"), vulnerable: make_list("lt 2.6.7-r1")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "sys-kernel/hardened-dev-sources", unaffected: make_list("ge 2.6.7-r1"), vulnerable: make_list("lt 2.6.7-r1")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "sys-kernel/aa-sources", unaffected: make_list("ge 2.6.5-r5", "lt 2.6"), vulnerable: make_list("lt 2.6.5-r5")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "sys-kernel/gentoo-dev-sources", unaffected: make_list("ge 2.6.7-r7"), vulnerable: make_list("lt 2.6.7-r7")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "sys-kernel/usermode-sources", unaffected: make_list("ge 2.6.6-r2", "lt 2.6"), vulnerable: make_list("lt 2.6.6-r2")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "sys-kernel/development-sources", unaffected: make_list("ge 2.6.8"), vulnerable: make_list("lt 2.6.8")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "sys-kernel/mips-sources", unaffected: make_list("ge 2.6.4-r4", "lt 2.6"), vulnerable: make_list("lt 2.6.4-r4")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "sys-kernel/uclinux-sources", unaffected: make_list("ge 2.6.7_p0-r1", "lt 2.6"), vulnerable: make_list("lt 2.6.7_p0")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "sys-kernel/mm-sources", unaffected: make_list("ge 2.6.7-r4", "lt 2.6"), vulnerable: make_list("lt 2.6.7-r4")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "sys-kernel/pegasos-dev-sources", unaffected: make_list("ge 2.6.7-r1"), vulnerable: make_list("lt 2.6.7-r1")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "sys-kernel/ck-sources", unaffected: make_list("ge 2.6.7-r2", "lt 2.6"), vulnerable: make_list("lt 2.6.7-r2")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "sys-kernel/hppa-dev-sources", unaffected: make_list("ge 2.6.7_p1-r1"), vulnerable: make_list("lt 2.6.7_p1-r1")
)) { security_hole(0); exit(0); }
