#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2006:092
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(21603);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2006-1655");
 
 name["english"] = "MDKSA-2006:092: mpg123";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2006:092 (mpg123).



An unspecified vulnerability in mpg123 0.59r allows user-complicit

attackers to trigger a segmentation fault and possibly have other impacts

via a certain MP3 file, as demonstrated by mpg1DoS3.



Packages have been patched to correct this issue.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2006:092
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the mpg123 package";
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
if ( rpm_check( reference:"mpg123-0.59r-23.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"mpg123-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2006-1655", value:TRUE);
}
