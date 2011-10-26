#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:197
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20125);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-0602", "CVE-2005-2475");
 
 name["english"] = "MDKSA-2005:197: unzip";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:197 (unzip).



Unzip 5.51 and earlier does not properly warn the user when extracting setuid
or setgid files, which may allow local users to gain privileges.
(CVE-2005-0602) Imran Ghory found a race condition in the handling of output
files. While a file was unpacked by unzip, a local attacker with write
permissions to the target directory could exploit this to change the
permissions of arbitrary files of the unzip user. This affects versions of
unzip 5.52 and lower (CVE-2005-2475) The updated packages have been patched to
address these issues.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:197
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the unzip package";
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
if ( rpm_check( reference:"unzip-5.51-1.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"unzip-5.51-1.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"unzip-5.52-1.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"unzip-", release:"MDK10.1")
 || rpm_exists(rpm:"unzip-", release:"MDK10.2")
 || rpm_exists(rpm:"unzip-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2005-0602", value:TRUE);
 set_kb_item(name:"CVE-2005-2475", value:TRUE);
}
