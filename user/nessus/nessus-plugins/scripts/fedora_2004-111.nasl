#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13692);
 script_bugtraq_id(10143, 10179, 10233);
 script_version ("$Revision: 1.6 $");
 script_cve_id("CVE-2004-0109", "CVE-2004-0133", "CVE-2004-0178", "CVE-2004-0181", "CVE-2004-0228", "CVE-2004-0394", "CVE-2004-0424");
 
 name["english"] = "Fedora Core 1 2004-111: kernel";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2004-111 (kernel).

The kernel package contains the Linux kernel (vmlinuz), the core of your
Fedora Core Linux operating system.  The kernel handles the basic functions
of the operating system:  memory allocation, process allocation, device
input and output, etc.

Update Information:

A memory leak was fixed in an error path in the do_fork() routine.
This was unlikely to have caused problems in real world situations.

The information leak fixed in the previous errata was also found
to affect XFS and JFS. The Common Vulnerabilities and
Exposures project (cve.mitre.org) assigned the names
CVE-2004-0133 and CVE-2004-0181 respectively.

A vulnerability in the OSS code for SoundBlaster 16 devices
was discovered by Andreas Kies.  It is possible for local users with
access to the sound system to crash the machine (CVE-2004-0178).

An automated checked from http://www.coverity.com highlighted a
range checking bug in the i810 DRM driver. This was fixed by
Andrea Arcangeli and Chris Wright.

Arjan van de Ven discovered the framebuffer code was doing direct
userspace accesses instead of using correct interfaces to write
to userspace.

Brad Spengler found a signedness issue in the cpufreq proc handler
which could lead to users being able to read arbitary regions of
kernel memory. This was fixed by Dominik Brodowski.

Shaun Colley found a potential buffer overrun in the panic() function.
As this function does not ever return, it is unlikely that this is
exploitable, but has been fixed nonetheless.  The Common Vulnerabilities
and Exposures project (cve.mitre.org) assigned the name CVE-2004-0394
to this issue.

Paul Starzetz and Wojciech Purczynski found a lack of bounds
checking in the MCAST_MSFILTER socket option which allows user code
to write into kernel space, potentially giving the attacker full
root priveledges. There has already been proof of concept code published
exploiting this hole in a local denial-of-service manner.
http://www.isec.pl/vulnerabilities/isec-0015-msfilter.txt has more
information. The Common Vulnerabilities and Exposures project (cve.mitre.org)
assigned the name CVE-2004-0424 to this issue.

The previous security errata actually missed fixes for several important
problems. This has been corrected in this update.



Solution : http://www.fedoranews.org/updates/FEDORA-2004-111.shtml
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the kernel package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Fedora Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"kernel-source-2.4.22-1.2188.nptl", release:"FC1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.4.22-1.2188.nptl", release:"FC1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-BOOT-2.4.22-1.2188.nptl", release:"FC1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-debuginfo-2.4.22-1.2188.nptl", release:"FC1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"kernel-", release:"FC1") )
{
 set_kb_item(name:"CVE-2004-0109", value:TRUE);
 set_kb_item(name:"CVE-2004-0133", value:TRUE);
 set_kb_item(name:"CVE-2004-0178", value:TRUE);
 set_kb_item(name:"CVE-2004-0181", value:TRUE);
 set_kb_item(name:"CVE-2004-0228", value:TRUE);
 set_kb_item(name:"CVE-2004-0394", value:TRUE);
 set_kb_item(name:"CVE-2004-0424", value:TRUE);
}
