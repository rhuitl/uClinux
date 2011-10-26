#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20872);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2006-0095", "CVE-2006-0454");
 
 name["english"] = "Fedora Core 4 2006-102: kernel";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2006-102 (kernel).

The kernel package contains the Linux kernel (vmlinuz), the core of any
Linux operating system.  The kernel handles the basic functions
of the operating system:  memory allocation, process allocation, device
input and output, etc.

Update Information:

This update fixes a remotely exploitable denial of service
attack in the icmp networking code (CVE-2006-0454).  An
information leak has also been fixed (CVE-2006-0095), and
some debugging patches that had accidentally been left
applied in the previous update have been removed, restoring
the functionality of the 'quiet' argument.



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
if ( rpm_check( reference:"kernel-2.6.15-1.1831_FC4", prefix:"kernel-", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"kernel-", release:"FC4") )
{
 set_kb_item(name:"CVE-2006-0095", value:TRUE);
 set_kb_item(name:"CVE-2006-0454", value:TRUE);
}
