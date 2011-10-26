#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13669);
 script_bugtraq_id(9154);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2003-0984", "CVE-2003-0985");
 
 name["english"] = "Fedora Core 1 2003-046: kernel";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2003-046 (kernel).

The kernel package contains the Linux kernel (vmlinuz), the core of your
Red Hat Linux operating system.  The kernel handles the basic functions
of the operating system:  memory allocation, process allocation, device
input and output, etc.

Paul Starzetz discovered a flaw in bounds checking in mremap() in the Linux
kernel versions 2.4.23 and previous which may allow a local attacker to
gain root privileges.  No exploit is currently available; however, it is
believed that this issue is exploitable (although not trivially.) The
Common Vulnerabilities and Exposures project (cve.mitre.org) has assigned
the name CVE-2003-0985 to this issue.

All users are advised to upgrade to these errata packages, which contain a
backported security patch that corrects this issue.  

Red Hat would like to thank Paul Starzetz from ISEC for disclosing this
issue as well as Andrea Arcangeli and Solar Designer for working on the patch.

These packages also contain a fix for a minor information leak in the real
time clock (rtc) routines. The Common Vulnerabilities and Exposures project
(cve.mitre.org) has assigned the name CVE-2003-0984 to this issue.


* Wed Dec 24 2003 Dave Jones <davej@redhat.com>
- Fix mremap corner case.

* Tue Dec 23 2003 Dave Jones <davej@redhat.com>
- Numerous USB fixes (#110307, #90442, #107929, #110872)

* Tue Dec 16 2003 Dave Jones <davej@redhat.com>
- Fix leak in CDROM IOCTL. (#112249)


Solution : http://www.fedoranews.org/updates/FEDORA-2003-046.shtml
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
if ( rpm_check( reference:"kernel-2.4.22-1.2138.nptl", prefix:"kernel-", release:"FC1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"kernel-", release:"FC1") )
{
 set_kb_item(name:"CVE-2003-0984", value:TRUE);
 set_kb_item(name:"CVE-2003-0985", value:TRUE);
}
