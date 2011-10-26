#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13685);
 script_bugtraq_id(10151, 9570);
 script_version ("$Revision: 1.6 $");
 script_cve_id("CVE-2004-0003", "CVE-2004-0109", "CVE-2004-0133");
 
 name["english"] = "Fedora Core 1 2004-101: kernel";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2004-101 (kernel).

The kernel package contains the Linux kernel (vmlinuz), the core of your
Fedora Core Linux operating system.  The kernel handles the basic functions
of the operating system:  memory allocation, process allocation, device
input and output, etc.

Update Information:

iDefense reported a buffer overflow flaw in the ISO9660 filesystem code.
An attacker could create a malicious filesystem in such a way that they
could gain root privileges if that filesystem is mounted. The Common
Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
CVE-2004-0109 to this issue.

Solar Designer from OpenWall discovered a minor information leak in the
ext3 filesystem code due to the lack of initialization of journal
descriptor blocks. This flaw has only minor security implications and
exploitation requires privileged access to the raw device. The Common
Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
CVE-2004-0133 to this issue.

These packages also contain an updated fix with additional checks for
issues in the R128 Direct Render Infrastructure. The Common
Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
CVE-2004-0003 to this issue.

Additionally, additional hardening of the mremap function was applied to
prevent a potential local denial of service attack.

The low latency patch applied in previous kernels has also been found
to cause stability problems under certain conditions. It has been disabled in
this update whilst further investigation occurs.



Solution : http://www.fedoranews.org/updates/FEDORA-2004-101.shtml
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
if ( rpm_check( reference:"kernel-source-2.4.22-1.2179.nptl", release:"FC1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.4.22-1.2179.nptl", release:"FC1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-BOOT-2.4.22-1.2179.nptl", release:"FC1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-debuginfo-2.4.22-1.2179.nptl", release:"FC1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"kernel-", release:"FC1") )
{
 set_kb_item(name:"CVE-2004-0003", value:TRUE);
 set_kb_item(name:"CVE-2004-0109", value:TRUE);
 set_kb_item(name:"CVE-2004-0133", value:TRUE);
}
