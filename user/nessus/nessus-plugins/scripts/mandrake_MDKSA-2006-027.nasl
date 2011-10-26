#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2006:027
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20832);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2005-0758");
 
 name["english"] = "MDKSA-2006:027: gzip";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2006:027 (gzip).



Zgrep in gzip before 1.3.5 does not properly sanitize arguments, which allows
local users to execute arbitrary commands via filenames that are injected into
a sed script. This was previously corrected in MDKSA-2005:092, however the fix
was incomplete. These updated packages provide a more comprehensive fix to the
problem.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2006:027
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the gzip package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 family["english"] = "Mandrake Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"gzip-1.2.4a-13.3.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gzip-1.2.4a-14.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gzip-1.2.4a-15.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"gzip-", release:"MDK10.1")
 || rpm_exists(rpm:"gzip-", release:"MDK10.2")
 || rpm_exists(rpm:"gzip-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2005-0758", value:TRUE);
}
