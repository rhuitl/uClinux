#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13733);
 script_version ("$Revision: 1.2 $");
 
 name["english"] = "Fedora Core 2 2004-202: kernel";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2004-202 (kernel).

The kernel package contains the Linux kernel (vmlinuz), the core of any
Linux operating system.  The kernel handles the basic functions
of the operating system:  memory allocation, process allocation, device
input and output, etc.

Update Information:

This security update fixes the remote DoS possibility identified and fixed
by Adam Osuchowski and Tomasz Dubinski in the netfilter code of the 2.6
kernel. Note that this remote DoS can only be triggered when using the
rarely used '-p tcp --tcp-option' options in the netfilter firewall
subsystem. Fedora Core 2 systems are not vulnerable unless the administrator
manually configured this rarely used option.

For more information see
http://www.securityfocus.com/archive/1/367615/2004-06-27/2004-07-03/0



Solution : http://www.fedoranews.org/updates/FEDORA-2004-202.shtml
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
if ( rpm_check( reference:"kernel-2.6.6-1.435.2.1", prefix:"kernel-", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
