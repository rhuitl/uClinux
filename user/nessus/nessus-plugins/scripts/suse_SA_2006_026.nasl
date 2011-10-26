#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2006:026
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(21622);
 script_version ("$Revision: 1.1 $");
 
 name["english"] = "SUSE-SA:2006:026: foomatic-filters";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2006:026 (foomatic-filters).


A bug in cupsomatic/foomatic-filters that allowed remote printer
users to execute arbitrary commands with the UID of the printer
daemon has been fixed (CVE-2004-0801).

While the same problem was fixed in earlier products, the fix got
lost during package upgrade of foomatic-filters for SUSE Linux 9.3.

Only SUSE Linux 9.3, 10.0 and 10.1 still contained this bug.

Solution : http://www.suse.de/security/advisories/2006-05-30.html
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the foomatic-filters package";
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
if ( rpm_check( reference:"foomatic-filters-3.0.2-4.2", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"foomatic-filters-3.0.2-3.2", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
