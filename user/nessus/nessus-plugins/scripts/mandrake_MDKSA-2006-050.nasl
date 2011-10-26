#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2006:050
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(21003);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2005-4667");
 
 name["english"] = "MDKSA-2006:050: unzip";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2006:050 (unzip).



A buffer overflow was foiund in how unzip handles file name arguments. If a
user could tricked into processing a specially crafted, excessively long file
name with unzip, an attacker could execute arbitrary code with the user's
privileges. The updated packages have been patched to address this issue.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2006:050
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the unzip package";
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
if ( rpm_check( reference:"unzip-5.51-1.3.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"unzip-5.52-1.3.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"unzip-", release:"MDK10.2")
 || rpm_exists(rpm:"unzip-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2005-4667", value:TRUE);
}
