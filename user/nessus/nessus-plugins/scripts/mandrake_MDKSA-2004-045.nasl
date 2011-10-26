#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2004:045
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14144);
 script_version ("$Revision: 1.3 $");
 
 name["english"] = "MDKSA-2004:045: passwd";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2004:045 (passwd).


Steve Grubb found some problems in the passwd program. Passwords given to passwd
via stdin are one character shorter than they are supposed to be. He also
discovered that pam may not have been sufficiently initialized to ensure safe
and proper operation. A few small memory leaks have been fixed as well.
The updated packages are patched to correct these problems.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:045
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the passwd package";
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
if ( rpm_check( reference:"passwd-0.68-2.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"passwd-0.68-2.2.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"passwd-0.68-2.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
