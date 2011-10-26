#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2001:084
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13897);
 script_version ("$Revision: 1.3 $");
 
 name["english"] = "MDKSA-2001:084: util-linux";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2001:084 (util-linux).


Tarhon-Onu Victor found a problem in /bin/login's PAM implementation. It stored
the value of a static pwent buffer across PAM calls, and when used with some PAM
modules in non-default configurations (ie. using pam_limits), it would overwrite
the buffer and cause the user to get the credentials of another user. Thanks to
Olaf Kirch for providing the patch to fix the problem.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2001:084
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the util-linux package";
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
if ( rpm_check( reference:"util-linux-2.10s-3.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"util-linux-2.11h-3.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
