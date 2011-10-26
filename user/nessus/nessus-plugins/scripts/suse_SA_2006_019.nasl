#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2006:019
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(21163);
 script_version ("$Revision: 1.1 $");
 
 name["english"] = "SUSE-SA:2006:019: freeradius";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2006:019 (freeradius).


Insufficient input validation was being done in the EAP-MSCHAPv2
state machine of the FreeRADIUS authentication server.

A malicious attacker could manipulate their EAP-MSCHAPv2 client state
machine to potentially convince the server to bypass authentication
checks. This bypassing could also result in the server crashing.

This is tracked by the Mitre CVE ID CVE-2006-1354.


Solution : http://www.suse.de/security/advisories/2006_19_freeradius.html
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the freeradius package";
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
if ( rpm_check( reference:"freeradius-1.0.4-4.2", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"freeradius-1.0.5-2.14", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"freeradius-1.0.0-5.8", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"freeradius-1.0.2-5.7", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
