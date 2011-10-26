#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(21252);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2006-0744", "CVE-2006-1055", "CVE-2006-1056", "CVE-2006-1522", "CVE-2006-1524", "CVE-2006-1525");
 
 name["english"] = "Fedora Core 5 2006-421: kernel";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2006-421 (kernel).

The kernel package contains the Linux kernel (vmlinuz), the core of any
Linux operating system.  The kernel handles the basic functions
of the operating system:  memory allocation, process allocation, device
input and output, etc.

Update Information:

This update includes a number of security issues that have been
fixed upstream over the last week or so.

i386/x86-64: Fix x87 information leak between processes
(CVE-2006-1056)
ip_route_input panic fix (CVE-2006-1525)
fix MADV_REMOVE vulnerability (CVE-2006-1524)
shmat: stop mprotect from giving write permission to a
readonly attachment (CVE-2006-1524)
Fix MPBL0010 driver insecure sysfs permissions
x86_64: When user could have changed RIP always force IRET
(CVE-2006-0744)
Fix RCU signal handling
Keys: Fix oops when adding key to non-keyring (CVE-2006-1522)
sysfs: zero terminate sysfs write buffers (CVE-2006-1055)

It also includes various other fixes from the -stable tree.
Full changelogs are available from:

[8]http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.16.9
[9]http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.16.8
[10]http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.16.7
[11]http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.16.6
[12]http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.16.5
[13]http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.16.4
[14]http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.16.3
[15]http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.16.2



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
if ( rpm_check( reference:"kernel-2.6.16-1.2096_FC5", prefix:"kernel-", release:"FC5") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"kernel-", release:"FC5") )
{
 set_kb_item(name:"CVE-2006-0744", value:TRUE);
 set_kb_item(name:"CVE-2006-1055", value:TRUE);
 set_kb_item(name:"CVE-2006-1056", value:TRUE);
 set_kb_item(name:"CVE-2006-1522", value:TRUE);
 set_kb_item(name:"CVE-2006-1524", value:TRUE);
 set_kb_item(name:"CVE-2006-1525", value:TRUE);
}
