#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14203);
 script_version ("$Revision: 1.2 $");
 
 name["english"] = "Fedora Core 2 2004-247: kernel";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2004-247 (kernel).

The kernel package contains the Linux kernel (vmlinuz), the core of any
Linux operating system.  The kernel handles the basic functions
of the operating system:  memory allocation, process allocation, device
input and output, etc.

Update Information:

This update kernel for Fedora Core 2 contains the security fixes as found by
Paul Starzetz from isec.pl. In addition this kernel contains a significant
number of bugfixes that are inherited from the newer kernel.org kernel this
release is based on.



Solution : http://www.fedoranews.org/updates/FEDORA-2004-247.shtml
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
if ( rpm_check( reference:"kernel-2.6.7-1.494.2.2", prefix:"kernel-", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
