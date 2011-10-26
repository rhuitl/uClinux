#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2006:022
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(21290);
 script_version ("$Revision: 1.1 $");
 
 name["english"] = "SUSE-SA:2006:022: MozillaThunderbird";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2006:022 (MozillaThunderbird).


Various security bugs have been fixed in Mozilla Thunderbird, bringing
it up to bugfix level of version 1.0.8.

This also catches up on earlier Thunderbird security releases.


Solution : http://www.suse.de/security/advisories/2006_04_25.html
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the MozillaThunderbird package";
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
if ( rpm_check( reference:"MozillaThunderbird-1.0.8-0.2", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MozillaThunderbird-1.0.8-0.1", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MozillaThunderbird-1.0.8-0.2", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MozillaThunderbird-1.0.8-0.2", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
