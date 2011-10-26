#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:067
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18002);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2004-1772", "CVE-2004-1773");
 
 name["english"] = "MDKSA-2005:067: sharutils";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:067 (sharutils).



Shaun Colley discovered a buffer overflow in shar that was triggered by output
files (using -o) with names longer than 49 characters which could be exploited
to run arbitrary attacker-specified code.

Ulf Harnhammar discovered that shar does not check the data length returned by
the wc command.

Joey Hess discovered that unshar would create temporary files in an insecure
manner which could allow a symbolic link attack to create or overwrite
arbitrary files with the privileges of the user using unshar.

The updated packages have been patched to correct these issues.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:067
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the sharutils package";
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
if ( rpm_check( reference:"sharutils-4.2.1-14.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sharutils-4.2.1-17.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"sharutils-", release:"MDK10.0")
 || rpm_exists(rpm:"sharutils-", release:"MDK10.1") )
{
 set_kb_item(name:"CVE-2004-1772", value:TRUE);
 set_kb_item(name:"CVE-2004-1773", value:TRUE);
}
