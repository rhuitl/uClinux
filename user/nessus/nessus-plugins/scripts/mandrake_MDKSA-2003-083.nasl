#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2003:083
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14065);
 script_bugtraq_id(8350);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2003-0656");
 
 name["english"] = "MDKSA-2003:083: eroaster";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2003:083 (eroaster).


A vulnerability was discovered in eroaster where it does not take any security
precautions when creating a temporary file for the lockfile. This vulnerability
could be exploited to overwrite arbitrary files with the privileges of the user
running eroaster.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:083
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the eroaster package";
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
if ( rpm_check( reference:"eroaster-2.1.0-6.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"eroaster-2.1.0-6.1mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"eroaster-", release:"MDK9.0")
 || rpm_exists(rpm:"eroaster-", release:"MDK9.1") )
{
 set_kb_item(name:"CVE-2003-0656", value:TRUE);
}
