#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20073);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CAN-2005-2973", "CAN-2005-3179", "CAN-2005-3180", "CAN-2005-3181");
 
 name["english"] = "Fedora Core 3 2005-1007: kernel";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2005-1007 (kernel).

The kernel package contains the Linux kernel (vmlinuz), the core of any
Linux operating system.  The kernel handles the basic functions
of the operating system:  memory allocation, process allocation, device
input and output, etc.

Update Information:

This update fixes the outstanding kernel security issues for
FC3, and fixes a number of regressions in the previous
update kernel.



Solution : Get the newest Fedora Updates
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the kernel package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Fedora Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"kernel-2.6.12-1.1380_FC3", prefix:"kernel-", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"kernel-", release:"FC3") )
{
 set_kb_item(name:"CAN-2005-2973", value:TRUE);
 set_kb_item(name:"CAN-2005-3179", value:TRUE);
 set_kb_item(name:"CAN-2005-3180", value:TRUE);
 set_kb_item(name:"CAN-2005-3181", value:TRUE);
}
