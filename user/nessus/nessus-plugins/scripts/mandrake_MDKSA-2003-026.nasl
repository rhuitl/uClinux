#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2003:026
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14010);
 script_bugtraq_id(6897);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2002-1509");
 
 name["english"] = "MDKSA-2003:026: shadow-utils";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2003:026 (shadow-utils).


The shadow-utils package contains the tool useradd, which is used to create or
update new user information. When useradd creates an account, it would create it
with improper permissions; instead of having it owned by the group mail, it
would be owned by the user's primary group. If this is a shared group (ie.
'users'), then all members of the shared group would be able to obtain access to
the mail spools of other members of the same group. A patch to useradd has been
applied to correct this problem.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:026
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the shadow-utils package";
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
if ( rpm_check( reference:"shadow-utils-20000902-2.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"shadow-utils-20000902-5.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"shadow-utils-20000902-8.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"shadow-utils-", release:"MDK8.1")
 || rpm_exists(rpm:"shadow-utils-", release:"MDK8.2")
 || rpm_exists(rpm:"shadow-utils-", release:"MDK9.0") )
{
 set_kb_item(name:"CVE-2002-1509", value:TRUE);
}
