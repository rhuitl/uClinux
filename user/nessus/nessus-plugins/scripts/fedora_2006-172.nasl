#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(21101);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2006-0745");
 
 name["english"] = "Fedora Core 5 2006-172: xorg-x11-server";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2006-172 (xorg-x11-server).

X.Org X11 X server

Update Information:

Coverity scanned the X.Org source code for problems and
reported their findings to the X.Org development team. Upon
analysis, Alan Coopersmith, a member of the X.Org
development team, noticed a couple of serious security
issues in the findings.  In particular, the Xorg server can
be exploited for root privilege escalation by passing a path
to malicious modules using the -modulepath command line
argument.  Also, the Xorg server can be exploited to
overwrite any root writable file on the filesystem with the
-logfile command line argument.


Solution : Get the newest Fedora Updates
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the xorg-x11-server package";
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
if ( rpm_check( reference:"xorg-x11-server-1.0.1-9", prefix:"xorg-x11-server-", release:"FC5") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"xorg-x11-server-", release:"FC5") )
{
 set_kb_item(name:"CVE-2006-0745", value:TRUE);
}
