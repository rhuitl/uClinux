#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13661);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2003-0859");
 
 name["english"] = "Fedora Core 1 2003-002: glibc";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2003-002 (glibc).

The glibc package contains standard libraries which are used by
multiple programs on the system. In order to save disk space and
memory, as well as to make upgrading easier, common system code is
kept in one place and shared between programs. This particular package
contains the most important sets of shared libraries: the standard C
library and the standard math library. Without these two libraries, a
Linux system will not function.

Update Information:

Herbert Xu reported that various applications can accept spoofed messages
sent on the kernel netlink interface by other users on the local machine.
This could lead to a local denial of service attack. The glibc function
getifaddrs uses netlink and could therefore be vulnerable to this issue.
The Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the name CVE-2003-0859 to this issue.

In addition to this this update fixes a couple of bugs.


Solution : http://www.fedoranews.org/updates/FEDORA-2003-002.shtml
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the glibc package";
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
if ( rpm_check( reference:"glibc-2.3.2-101.1", prefix:"glibc-", release:"FC1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"glibc-", release:"FC1") )
{
 set_kb_item(name:"CVE-2003-0859", value:TRUE);
}
