#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2006:023
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(21368);
 script_version ("$Revision: 1.1 $");
 
 name["english"] = "SUSE-SA:2006:023: xorg-x11-server";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2006:023 (xorg-x11-server).


Miscalculation of a buffer size in the X Render extension of the
X.Org X11 server could potentially be exploited by users to cause a
buffer overflow and run code with elevated privileges.


Solution : http://www.suse.de/security/advisories/2006_05_03.html
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
if ( rpm_check( reference:"xorg-x11-server-6.8.2-100.5", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-server-6.8.1-15.10", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-server-6.8.2-30.5", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
