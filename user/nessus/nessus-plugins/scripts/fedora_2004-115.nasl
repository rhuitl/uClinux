#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13694);
 script_bugtraq_id(9092);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2003-0856");
 
 name["english"] = "Fedora Core 1 2004-115: iproute";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2004-115 (iproute).

The iproute package contains networking utilities (ip and rtmon, for
example) which are designed to use the advanced networking
capabilities of the Linux 2.4.x and 2.6.x kernel.


Update Information:

This update of the iproute package fixes a security problem found in netlink. 
See CVE-2003-0856. All users of the netlink application are very strongly 
advised to update to these latest packages.



Solution : http://www.fedoranews.org/updates/FEDORA-2004-115.shtml
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the iproute package";
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
if ( rpm_check( reference:"iproute-2.4.7-13.2", release:"FC1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"iproute-debuginfo-2.4.7-13.2", release:"FC1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"iproute-", release:"FC1") )
{
 set_kb_item(name:"CVE-2003-0856", value:TRUE);
}
