#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2004:076
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14174);
 script_bugtraq_id(10819);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2004-0557");
 
 name["english"] = "MDKSA-2004:076: sox";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2004:076 (sox).


Ulf Harnhammar discovered two buffer overflows in SoX. They occur when the sox
or play commands handle malicious .WAV files.
Versions 12.17.4, 12.17.3 and 12.17.2 are vulnerable to these overflows.
12.17.1, 12.17 and 12.16 are some versions that are not.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:076
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the sox package";
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
if ( rpm_check( reference:"sox-12.17.4-2.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sox-devel-12.17.4-2.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sox-12.17.3-4.1.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sox-devel-12.17.3-4.1.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sox-12.17.4-2.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sox-devel-12.17.4-2.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"sox-", release:"MDK10.0")
 || rpm_exists(rpm:"sox-", release:"MDK9.1")
 || rpm_exists(rpm:"sox-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2004-0557", value:TRUE);
}
