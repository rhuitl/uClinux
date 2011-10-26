#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2001:078
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13893);
 script_version ("$Revision: 1.3 $");
 
 name["english"] = "MDKSA-2001:078: uucp";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2001:078 (uucp).


Zen Parse discovered that an argument handling problem that exists in the uucp
package can allow a local attacker to gain access to the uucp user or group.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2001:078
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the uucp package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Mandrake Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"uucp-1.06.1-14.1mdk", release:"MDK7.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"uucp-1.06.1-17.1mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"uucp-1.06.1-18.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
