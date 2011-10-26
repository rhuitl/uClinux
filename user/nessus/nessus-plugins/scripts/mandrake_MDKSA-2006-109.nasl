#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2006:109
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(21753);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2006-2197");
 
 name["english"] = "MDKSA-2006:109: wv2";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2006:109 (wv2).



A boundary checking error was discovered in the wv2 library, used for

accessing Microsoft Word documents. This error can lead to an integer

overflow induced by processing certain Word files.



The updated packages have been patched to correct these issues.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2006:109
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the wv2 package";
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
if ( rpm_check( reference:"libwv2_1-0.2.2-3.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libwv2_1-devel-0.2.2-3.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"wv2-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2006-2197", value:TRUE);
}
