#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2002:002-1
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13910);
 script_version ("$Revision: 1.4 $");
 
 name["english"] = "MDKSA-2002:002-1: mutt";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2002:002-1 (mutt).


Joost Pol reported a remotely exploitable buffer overflow in the mutt email
client. It is recommended that all mutt users upgrade their packages
immediately.
Update:
The previous packages released for 8.x were unable to recall postponed messages
due to an incorrect patch. These new packages also provide the compressed
folders patch that was unavailable when MDKSA-2002:002 was announced.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2002:002-1
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the mutt package";
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
if ( rpm_check( reference:"mutt-1.2.5i-6.1mdk", release:"MDK7.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mutt-1.2.5i-6.2mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mutt-1.3.25i-1.2mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mutt-1.3.25i-1.2mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
