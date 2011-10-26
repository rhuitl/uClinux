#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13679);
 script_bugtraq_id(9686, 9691);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2004-0010", "CVE-2004-0077");
 
 name["english"] = "Fedora Core 1 2004-079: kernel";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2004-079 (kernel).

The kernel package contains the Linux kernel (vmlinuz), the core of your
Fedora Core Linux operating system.  The kernel handles the basic functions
of the operating system:  memory allocation, process allocation, device
input and output, etc.

Update Information:

Paul Starzetz discovered a flaw in return value checking in mremap() in the
Linux kernel versions 2.4.24 and previous that may allow a local attacker
to gain root privileges.  No exploit is currently available; however this
issue is exploitable. The Common Vulnerabilities and Exposures project
(cve.mitre.org) has assigned the name CVE-2004-0077 to this issue.

Arjan van de Ven discovered a flaw in ncp_lookup() in ncpfs that could
allow local privilege escalation.  ncpfs is only used to allow a system to
mount volumes of NetWare servers or print to NetWare printers.  The Common
Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
CVE-2004-0010 to this issue.

All users are advised to upgrade to these errata packages, which contain
backported security patches that correct these issues.  

Red Hat would like to thank Paul Starzetz from ISEC for reporting the issue
CVE-2004-0077.



Solution : http://www.fedoranews.org/updates/FEDORA-2004-079.shtml
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
if ( rpm_check( reference:"kernel-2.4.22-1.2173.nptl", prefix:"kernel-", release:"FC1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"kernel-", release:"FC1") )
{
 set_kb_item(name:"CVE-2004-0010", value:TRUE);
 set_kb_item(name:"CVE-2004-0077", value:TRUE);
}
