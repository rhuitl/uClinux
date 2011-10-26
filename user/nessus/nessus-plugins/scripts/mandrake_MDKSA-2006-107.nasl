#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2006:107
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(21751);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2006-2916");
 
 name["english"] = "MDKSA-2006:107: arts";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2006:107 (arts).



A vulnerability in the artswrapper program, when installed setuid root,

could enable a local user to elevate their privileges to that of root.



By default, Mandriva Linux does not ship artswrapper setuid root,

however if a user or system administrator enables the setuid bit on

artswrapper, their system could be at risk,



The updated packages have been patched to correct these issues.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2006:107
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the arts package";
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
if ( rpm_check( reference:"arts-1.4.2-2.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libarts1-1.4.2-2.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libarts1-devel-1.4.2-2.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"arts-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2006-2916", value:TRUE);
}
