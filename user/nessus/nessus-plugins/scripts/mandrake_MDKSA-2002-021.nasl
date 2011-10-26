#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2002:021
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13929);
 script_version ("$Revision: 1.3 $");
 
 name["english"] = "MDKSA-2002:021: mod_frontpage";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2002:021 (mod_frontpage).


A problem was found in versions of improved mod_frontpage prior to 1.6.1
regarding a lack of boundary checks in fpexec.c. This means that the suid root
binary is exploitable for buffer overflows. This could be exploited by remote
attackers to execute arbitrary code on the server with superuser privileges.
Although there are no known exploits available, if you use mod_frontpage you are
strongly encouraged to upgrade.
This update for Mandrake Linux has been completely reworked and is easier to
configure and use, as well as supporting the new FrontPage 2002 extensions.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2002:021
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the mod_frontpage package";
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
if ( rpm_check( reference:"mod_frontpage-1.6.1-3.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mod_frontpage-1.6.1-3.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
