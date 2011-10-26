#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2001:087
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13900);
 script_version ("$Revision: 1.3 $");
 
 name["english"] = "MDKSA-2001:087: expect";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2001:087 (expect).


A packaging problem that can lead to a root compromise existed in the expect
package as provided in Mandrake Linux 8.1. expect would look for libraries in
the directory /home/snailtalk/tmp/tcltk-root/usr/lib before any other and if
such a user existed on the system, with rogue libraries, if root were to execute
expect, a compromise could occur.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2001:087
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the expect package";
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
if ( rpm_check( reference:"expect-8.3.3-9.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
