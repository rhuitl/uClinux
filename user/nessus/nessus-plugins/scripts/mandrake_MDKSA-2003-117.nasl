#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2003:117
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14099);
 script_version ("$Revision: 1.3 $");
 
 name["english"] = "MDKSA-2003:117: irssi";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2003:117 (irssi).


A vulnerability in versions of irssi prior to 0.8.9 would allow a remote user to
crash another user's irssi client provided that the client was on a non-x86
architecture or if the 'gui print text' signal is being used by some script or
plugin.
The updated packages provide 0.8.9 which corrects the problem.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:117
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the irssi package";
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
if ( rpm_check( reference:"irssi-0.8.9-0.1.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"irssi-devel-0.8.9-0.1.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"irssi-0.8.9-0.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"irssi-devel-0.8.9-0.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
