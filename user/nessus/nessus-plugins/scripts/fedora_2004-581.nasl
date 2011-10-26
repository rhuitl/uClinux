#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16097);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2004-1016", "CVE-2004-1017", "CVE-2004-1068", "CVE-2004-1137", "CVE-2004-1151");
 
 name["english"] = "Fedora Core 2 2004-581: kernel";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2004-581 (kernel).

The kernel package contains the Linux kernel (vmlinuz), the core of
any Linux operating system. The kernel handles the basic functions
of the operating system: memory allocation, process allocation, device
input and output, etc.

A large change over previous kernels has been made. The 4G:4G memory
split patch has been dropped, and Fedora kernels now revert back to
the upstream 3G:1G kernel/userspace split.

A number of security fixes are present in this update.


Solution : http://www.fedoranews.org/blog/index.php?p=239
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
if ( rpm_check( reference:"kernel-2.6.9-   Release : 1.11_FC2", prefix:"kernel-", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"kernel-", release:"FC2") )
{
 set_kb_item(name:"CVE-2004-1016", value:TRUE);
 set_kb_item(name:"CVE-2004-1017", value:TRUE);
 set_kb_item(name:"CVE-2004-1068", value:TRUE);
 set_kb_item(name:"CVE-2004-1137", value:TRUE);
 set_kb_item(name:"CVE-2004-1151", value:TRUE);
}
