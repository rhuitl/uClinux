#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2003:031-1
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14015);
 script_version ("$Revision: 1.4 $");
 
 name["english"] = "MDKSA-2003:031-1: usermode";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2003:031-1 (usermode).


The /usr/bin/shutdown command that comes with the usermode package can be
executed by local users to shutdown all running processes and drop into a root
shell. This command is not really needed to shutdown a system, so it has been
removed and all users are encouraged to upgrade. Please note that the user must
have local console access in order to obtain a root shell in this fashion.
Update:
The previous updated packages did not properly fix the problem. The pam files
that allow a (physically) local user to shutdown were not removed. This has been
corrected.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:031-1
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the usermode package";
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
if ( rpm_check( reference:"usermode-1.42-8.2mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"usermode-1.44-4.2mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"usermode-consoleonly-1.44-4.2mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
