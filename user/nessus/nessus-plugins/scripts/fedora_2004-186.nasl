#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13731);
 script_bugtraq_id(10279, 10352);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2004-0495", "CVE-2004-0535", "CVE-2004-0554", "CVE-2004-0587");
 
 name["english"] = "Fedora Core 1 2004-186: kernel";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2004-186 (kernel).

The kernel package contains the Linux kernel (vmlinuz), the core of your
Fedora Core Linux operating system.  The kernel handles the basic functions
of the operating system:  memory allocation, process allocation, device
input and output, etc.

Update Information:

Numerous problems referencing userspace memory were identified in several
device drivers by Al Viro using the sparse tool.  The Common Vulnerabilities
and Exposures project (cve.mitre.org) assigned the name CVE-2004-0495 to this issue.

A problem was found where userspace code could execute certain floating
point instructions from signal handlers which would cause the kernel
to lock up.  The Common Vulnerabilities and Exposures project (cve.mitre.org)
assigned the name CVE-2004-0554 to this issue.

Previous kernels contained a patch against the framebuffer ioctl
code which turned out to be unnecessary. This has been dropped
in this update.

A memory leak in the E1000 network card driver has been fixed.
The Common Vulnerabilities and Exposures project (cve.mitre.org) assigned
the name CVE-2004-0535 to this issue.

Previously, inappropriate permissions were set on /proc/scsi/qla2300/HbaApiNode
The Common Vulnerabilities and Exposures project (cve.mitre.org) assigned
the name CVE-2004-0587 to this issue.

Support for systems with more than 4GB of memory was previously unavailable.
The 686 SMP kernel now supports this configuration. (Bugzilla #122960)
Support for SMP on 586's was also previously not included.
This has also been rectified. (Bugzilla #111871)



Solution : http://www.fedoranews.org/updates/FEDORA-2004-186.shtml
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
if ( rpm_check( reference:"kernel-source-2.4.22-1.2194.nptl", release:"FC1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.4.22-1.2194.nptl", release:"FC1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-BOOT-2.4.22-1.2194.nptl", release:"FC1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-debuginfo-2.4.22-1.2194.nptl", release:"FC1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"kernel-", release:"FC1") )
{
 set_kb_item(name:"CVE-2004-0495", value:TRUE);
 set_kb_item(name:"CVE-2004-0535", value:TRUE);
 set_kb_item(name:"CVE-2004-0554", value:TRUE);
 set_kb_item(name:"CVE-2004-0587", value:TRUE);
}
