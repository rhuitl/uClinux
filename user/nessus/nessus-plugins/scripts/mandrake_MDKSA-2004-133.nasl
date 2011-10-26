#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2004:133
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(15738);
 script_version ("$Revision: 1.2 $");
 
 name["english"] = "MDKSA-2004:133: sudo";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2004:133 (sudo).



Liam Helmer discovered a flow in sudo's environment sanitizing. This flaw could
allow a malicious users with permission to run a shell script that uses the
bash shell to run arbitrary commands.

The problem is fixed in sudo 1.6.8p2; the provided packages have been patched
to correct the issue.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:133
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the sudo package";
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
if ( rpm_check( reference:"sudo-1.6.7-0.p5.2.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sudo-1.6.8p1-1.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sudo-1.6.7-0.p5.1.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
