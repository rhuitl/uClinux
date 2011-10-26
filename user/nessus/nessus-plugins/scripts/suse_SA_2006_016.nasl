#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2006:016
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(21137);
 script_version ("$Revision: 1.1 $");
 
 name["english"] = "SUSE-SA:2006:016: xorg-x11-server";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2006:016 (xorg-x11-server).


A programming flaw in the X.Org X Server allows local attackers to
gain root access when the server is setuid root, as is the default
in SUSE Linux 10.0.  This flaw was spotted by the Coverity project.

Only SUSE Linux 10.0 is affected, older products do not include the
problematic piece of code.

This problem is tracked by the Mitre CVE ID CVE-2006-0745.


Solution : http://www.suse.de/security/advisories/2006_16_xorgx11server.html
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the xorg-x11-server package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 family["english"] = "SuSE Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"xorg-x11-server-6.8.2-100.4", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
