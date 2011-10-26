#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13664);
 script_version ("$Revision: 1.2 $");
 
 name["english"] = "Fedora Core 1 2003-026-1: kernel";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2003-026-1 (kernel).

The kernel package contains the Linux kernel (vmlinuz), the core of your
Red Hat Linux operating system.  The kernel handles the basic functions
of the operating system:  memory allocation, process allocation, device
input and output, etc.


THIS IS NOT AN OFFICIAL ANNOUNCEMENT FROM FEDORA PROJECT.
WE HAVE NOT RECEIVED THE OFFICIAL ANNOUNCEMENT AS OF 4:37PM 12/24/03 YET
WE WILL REPLACE WITH THE OFFICIAL ANNOUNCMENT AS SOON AS WE RECEIVE.
IN THE MEANTIME, HERE IS WHAT HAS CHANGED SINCE LAST KERNEL UPDATE ON 12/02/03



Solution : http://www.fedoranews.org/updates/FEDORA-2003-026-1.shtml
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
if ( rpm_check( reference:"kernel-2.4.22-1.2135.nptl", prefix:"kernel-", release:"FC1") )
{
 security_hole(0);
 exit(0);
}
