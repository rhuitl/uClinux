#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13737);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2004-0497");
 
 name["english"] = "Fedora Core 1 2004-206: kernel";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2004-206 (kernel).

The kernel package contains the Linux kernel (vmlinuz), the core of your
Fedora Core Linux operating system.  The kernel handles the basic functions
of the operating system:  memory allocation, process allocation, device
input and output, etc.

Update Information:

During an audit of the Linux kernel, SUSE discovered a flaw that allowed
a user to make unauthorized changes to the group ID of files in certain
circumstances. In the 2.4 kernel, as shipped with Fedora Core 1,
the only way this could happen is through the kernel nfs server.
A user on a system that mounted a remote file system from a vulnerable
machine may be able to make unauthorized changes to the group ID of
exported files. The Common Vulnerabilities and Exposures project
(cve.mitre.org) has assigned the name CVE-2004-0497 to this issue.
Only Fedora Core 1 systems that are configured to share
file systems via NFS are affected by this issue.

Additionally, a number of issues were discovered with the
Broadcom 5820 driver.  Until such time that these get fixed,
this driver has been disabled.

All Fedora Core 1 users are advised to upgrade their kernels
to the packages associated with their machine architectures
and configurations as listed in this erratum.



Solution : http://www.fedoranews.org/updates/FEDORA-2004-206.shtml
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
if ( rpm_check( reference:"kernel-source-2.4.22-1.2197.nptl", release:"FC1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.4.22-1.2197.nptl", release:"FC1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-BOOT-2.4.22-1.2197.nptl", release:"FC1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-debuginfo-2.4.22-1.2197.nptl", release:"FC1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"kernel-", release:"FC1") )
{
 set_kb_item(name:"CVE-2004-0497", value:TRUE);
}
