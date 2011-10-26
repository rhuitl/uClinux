#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2006:117-1
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(22013);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2006-2200");
 
 name["english"] = "MDKSA-2006:117-1: libmms";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2006:117-1 (libmms).



Stack-based buffer overflow in MiMMS 0.0.9 allows remote attackers to cause

a denial of service (application crash) and possibly execute arbitrary code

via the (1) send_command, (2) string_utf16, (3) get_data, and (4)

get_media_packet functions, and possibly other functions. Libmms uses the

same vulnerable code.



Update:



The previous update for libmms had an incorrect/incomplete patch. This

update includes a more complete fix for the issue.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2006:117-1
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the libmms package";
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
if ( rpm_check( reference:"libmms0-0.1-1.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libmms0-devel-0.1-1.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"libmms-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2006-2200", value:TRUE);
}
