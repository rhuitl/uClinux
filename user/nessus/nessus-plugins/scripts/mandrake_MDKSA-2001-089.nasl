#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2001:089
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13902);
 script_version ("$Revision: 1.3 $");
 
 name["english"] = "MDKSA-2001:089: postfix";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2001:089 (postfix).


Wietse Venema, the author of postfix, reported a vulnerability in the SMTP
server where a remote attacker could execute a Denial of Service attack on it.
The SMTP session log could grow to an unreasonable size and could possibly
exhause the server's memory if no other limits were enforced.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2001:089
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the postfix package";
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
if ( rpm_check( reference:"postfix-19991231-6.1mdk", release:"MDK7.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postfix-19991231_pl08-5.1mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postfix-20010228-6.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postfix-20010228-15.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
