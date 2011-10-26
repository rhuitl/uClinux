#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:039
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(17131);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2004-1180");
 
 name["english"] = "MDKSA-2005:039: rwho";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:039 (rwho).



A vulnerability in rwhod was discovered by 'Vlad902' that can be abused to
crash the listening process (the broadcasting process is not affected). This
vulnerability only affects little endian architectures.

The updated packages have been patched to correct the problem.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:039
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the rwho package";
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
if ( rpm_check( reference:"rwho-0.17-10.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"rwho-0.17-10.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"rwho-", release:"MDK10.0")
 || rpm_exists(rpm:"rwho-", release:"MDK10.1") )
{
 set_kb_item(name:"CVE-2004-1180", value:TRUE);
}
