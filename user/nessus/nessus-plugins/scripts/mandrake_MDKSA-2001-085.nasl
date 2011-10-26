#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2001:085
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13898);
 script_version ("$Revision: 1.3 $");
 
 name["english"] = "MDKSA-2001:085: procmail";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2001:085 (procmail).


In older versions of procmail, it is possible to crash procmail by sending it
certain signals. If procmail is installed setuid, this could be exploited to
gain unauthorized privilege. This problem is fixed in unstable version 3.20 and
stable version 3.15.2.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2001:085
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the procmail package";
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
if ( rpm_check( reference:"procmail-3.15.2-1.4mdk", release:"MDK7.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"procmail-3.15.2-1.3mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"procmail-3.15.2-1.2mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"procmail-3.22-1.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
