#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2004:039
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14138);
 script_bugtraq_id(10242);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2004-0226", "CVE-2004-0231", "CVE-2004-0232");
 
 name["english"] = "MDKSA-2004:039: mc";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2004:039 (mc).


Several vulnerabilities in Midnight Commander were found by Jacub Jelinek. This
includes several buffer overflows (CVE-2004-0226), as well as a format string
issue (CVE-2004-0232), and an issue with temporary file and directory creation
(CVE-2004-0231). Most of the included fixes are backports from CVS, done by
Andrew V. Samoilov and Pavel Roskin.
The updated packages are patched to correct these problems.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:039
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the mc package";
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
if ( rpm_check( reference:"mc-4.6.0-6.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mc-4.6.0-4.2.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mc-4.6.0-4.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"mc-", release:"MDK10.0")
 || rpm_exists(rpm:"mc-", release:"MDK9.1")
 || rpm_exists(rpm:"mc-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2004-0226", value:TRUE);
 set_kb_item(name:"CVE-2004-0231", value:TRUE);
 set_kb_item(name:"CVE-2004-0232", value:TRUE);
}
