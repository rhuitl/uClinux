#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:089
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18305);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2002-0137", "CVE-2002-0138");
 
 name["english"] = "MDKSA-2005:089: cdrdao";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:089 (cdrdao).



The cdrdao package contains two vulnerabilities; the first allows local users
to read arbitrary files via the show-data command and the second allows local
users to overwrite arbitrary files via a symlink attack on the ~/.cdrdao
configuration file. This can also lead to elevated privileges (a root shell)
due to cdrdao being installed suid root.

The provided packages have been patched to correct these issues.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:089
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the cdrdao package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Mandrake Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"cdrdao-1.1.8-2.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cdrdao-gcdmaster-1.1.8-2.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cdrdao-1.1.9-6.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cdrdao-gcdmaster-1.1.9-6.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cdrdao-1.1.9-7.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cdrdao-gcdmaster-1.1.9-7.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"cdrdao-", release:"MDK10.0")
 || rpm_exists(rpm:"cdrdao-", release:"MDK10.1")
 || rpm_exists(rpm:"cdrdao-", release:"MDK10.2") )
{
 set_kb_item(name:"CVE-2002-0137", value:TRUE);
 set_kb_item(name:"CVE-2002-0138", value:TRUE);
}
