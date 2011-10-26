#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20997);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2006-0555", "CVE-2006-0741");
 
 name["english"] = "Fedora Core 4 2006-131: kernel";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2006-131 (kernel).

The kernel package contains the Linux kernel (vmlinuz), the core of any
Linux operating system.  The kernel handles the basic functions
of the operating system:  memory allocation, process allocation, device
input and output, etc.

Update Information:

This update rebases to the latest -stable release
(2.6.15.5), which fixes a number of security problems.

- sys_mbind failed to sanity check its arguments, leading to
a potential local DoS.
- A specially crafted ELF executable could cause Intel EM64T
boxes to crash. (CVE-2006-0741)
- Normal users could panic NFS clients with direct I/O
(CVE-2006-0555)

Further information on 2.6.15.5 changes can be found in the
upstream changelog at
[8]http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.15.5

Further Fedora specific changes are detailed below.



Solution : Get the newest Fedora Updates
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the kernel package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 family["english"] = "Fedora Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"kernel-2.6.15-1.1833_FC4", prefix:"kernel-", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"kernel-", release:"FC4") )
{
 set_kb_item(name:"CVE-2006-0555", value:TRUE);
 set_kb_item(name:"CVE-2006-0741", value:TRUE);
}
