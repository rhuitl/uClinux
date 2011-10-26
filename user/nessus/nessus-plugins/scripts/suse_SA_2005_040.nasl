#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2005:040
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19249);
 script_version ("$Revision: 1.2 $");
 
 name["english"] = "SUSE-SA:2005:040: heimdal";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2005:040 (heimdal).


A remote buffer overflow has been fixed in the heimdal / kerberos
telnetd daemon which could lead to a remote user executing code as
root by overflowing a buffer.

This attack requires the use of the kerberized telnetd of the heimdal
suite, which is not used by default on SUSE systems.

This is tracked by the Mitre CVE ID CVE-2005-2040.


Solution : http://www.suse.de/security/advisories/2005_40_heimdal.html
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the heimdal package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "SuSE Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"heimdal-0.4e-413", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"heimdal-0.6-165", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"heimdal-0.6.1rc3-55.18", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"heimdal-0.6.2-8.4", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
