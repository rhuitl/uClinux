#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13736);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2004-0497");
 
 name["english"] = "Fedora Core 2 2004-205: kernel";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2004-205 (kernel).

The kernel package contains the Linux kernel (vmlinuz), the core of any
Linux operating system.  The kernel handles the basic functions
of the operating system:  memory allocation, process allocation, device
input and output, etc.

Update Information:

During an audit of the Linux kernel, SUSE discovered a flaw in the
Linux kernel that inappropriately allows an unprivileged user to
change the group ID of a file to his/her own group ID.
The Common Vulnerabilities and Exposures project
(cve.mitre.org) has assigned the name CVE-2004-0497 to this issue.

All Fedora Core 2 users are advised to upgrade their kernels to the
packages associated with their machine architectures and configurations
as listed in this erratum.



Solution : http://www.fedoranews.org/updates/FEDORA-2004-205.shtml
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
if ( rpm_check( reference:"kernel-2.6.6-1.435.2.3", prefix:"kernel-", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"kernel-", release:"FC2") )
{
 set_kb_item(name:"CVE-2004-0497", value:TRUE);
}
