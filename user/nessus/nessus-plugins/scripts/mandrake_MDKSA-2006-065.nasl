#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2006:065
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(21200);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2006-0051");
 
 name["english"] = "MDKSA-2006:065: kaffeine";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2006:065 (kaffeine).



Marcus Meissner discovered Kaffeine contains an unchecked buffer while creating
HTTP request headers for fetching remote RAM playlists, which allows
overflowing a heap allocated buffer. As a result, remotely supplied RAM
playlists can be used to execute arbitrary code on the client machine. Updated
packages have been patched to correct this issue.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2006:065
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the kaffeine package";
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
if ( rpm_check( reference:"kaffeine-0.7-6.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkaffeine0-0.7-6.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkaffeine0-devel-0.7-6.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"kaffeine-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2006-0051", value:TRUE);
}
