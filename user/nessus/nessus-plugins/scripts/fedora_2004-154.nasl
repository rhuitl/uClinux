#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13714);
 script_bugtraq_id(9092);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2003-0856");
 
 name["english"] = "Fedora Core 2 2004-154: net-tools";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2004-154 (net-tools).

The net-tools package contains basic networking tools, including
ifconfig, netstat, route, and others.


The code in netlink.c is based in part on the code of iproute. It
was not updated when CVE-2003-0856 was announced. The code in
question is within the netlink_listen & netlink_receive_dump
functions. They should both check the source of the packets by
looking at nl_pid and ensuring that it is 0 before performing
any reconfiguration of network interfaces.

These updated packages now contain the latest netplug daemon which fixes
that problem. All users of netplug are strongly encouraged to upgrade to
these new packages.



Solution : http://www.fedoranews.org/updates/FEDORA-2004-154.shtml
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the net-tools package";
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
if ( rpm_check( reference:"net-tools-1.60-25.1", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"net-tools-debuginfo-1.60-25.1", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"net-tools-", release:"FC2") )
{
 set_kb_item(name:"CVE-2003-0856", value:TRUE);
}
