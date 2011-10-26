#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2004:152
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16014);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2004-1139", "CVE-2004-1140", "CVE-2004-1141", "CVE-2004-1142");
 
 name["english"] = "MDKSA-2004:152: ethereal";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2004:152 (ethereal).



A number of vulnerabilities were discovered in Ethereal:

- Matthew Bing discovered a bug in DICOM dissection that could make Ethereal
crash (CVE-2004-1139) - An invalid RTP timestamp could make Ethereal hang and
create a large temporary file, possibly filling available disk space
(CVE-2004-1140) - The HTTP dissector could access previously-freed memory,
causing a crash (CVE-2004-1141) - Brian Caswell discovered that an improperly
formatted SMB packet could make Ethereal hang, maximizing CPU utilization
(CVE-2004-1142)

Ethereal 0.10.8 was released to correct these problems and is being provided.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:152
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the ethereal package";
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
if ( rpm_check( reference:"ethereal-0.10.8-0.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ethereal-0.10.8-0.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ethereal-tools-0.10.8-0.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libethereal0-0.10.8-0.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tethereal-0.10.8-0.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"ethereal-", release:"MDK10.0")
 || rpm_exists(rpm:"ethereal-", release:"MDK10.1") )
{
 set_kb_item(name:"CVE-2004-1139", value:TRUE);
 set_kb_item(name:"CVE-2004-1140", value:TRUE);
 set_kb_item(name:"CVE-2004-1141", value:TRUE);
 set_kb_item(name:"CVE-2004-1142", value:TRUE);
}
