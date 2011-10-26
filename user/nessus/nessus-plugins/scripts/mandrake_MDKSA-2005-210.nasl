#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:210
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20443);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2005-3183");
 
 name["english"] = "MDKSA-2005:210: w3c-libwww";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:210 (w3c-libwww).



Sam Varshavchik discovered the HTBoundary_put_block function in HTBound.c for
W3C libwww (w3c-libwww) allows remote servers to cause a denial of service
(segmentation fault) via a crafted multipart/byteranges MIME message that
triggers an out-of-bounds read. The updated packages have been patched to
address this issue.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:210
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the w3c-libwww package";
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
if ( rpm_check( reference:"w3c-libwww-5.4.0-3.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"w3c-libwww-apps-5.4.0-3.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"w3c-libwww-devel-5.4.0-3.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"w3c-libwww-5.4.0-5.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"w3c-libwww-apps-5.4.0-5.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"w3c-libwww-devel-5.4.0-5.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"w3c-libwww-5.4.0-5.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"w3c-libwww-apps-5.4.0-5.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"w3c-libwww-devel-5.4.0-5.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"w3c-libwww-", release:"MDK10.1")
 || rpm_exists(rpm:"w3c-libwww-", release:"MDK10.2")
 || rpm_exists(rpm:"w3c-libwww-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2005-3183", value:TRUE);
}
