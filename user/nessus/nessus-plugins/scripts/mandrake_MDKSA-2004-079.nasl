#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2004:079
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14328);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2004-0597", "CVE-2004-0598", "CVE-2004-0599");
 
 name["english"] = "MDKSA-2004:079: libpng";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2004:079 (libpng).


Chris Evans discovered numerous vulnerabilities in the libpng graphics library,
including a remotely exploitable stack-based buffer overrun in the
png_handle_tRNS function, dangerous code in png_handle_sBIT, a possible
NULL-pointer crash in png_handle_iCCP (which is also duplicated in multiple
other locations), a theoretical integer overflow in png_read_png, and integer
overflows during progressive reading.
All users are encouraged to upgrade immediately.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:079
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the libpng package";
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
if ( rpm_check( reference:"libpng3-1.2.5-10.5.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libpng3-devel-1.2.5-10.5.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libpng3-1.2.5-2.5.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libpng3-devel-1.2.5-2.5.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libpng3-static-devel-1.2.5-2.5.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libpng3-1.2.5-7.5.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libpng3-devel-1.2.5-7.5.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libpng3-static-devel-1.2.5-7.5.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"libpng-", release:"MDK10.0")
 || rpm_exists(rpm:"libpng-", release:"MDK9.1")
 || rpm_exists(rpm:"libpng-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2004-0597", value:TRUE);
 set_kb_item(name:"CVE-2004-0598", value:TRUE);
 set_kb_item(name:"CVE-2004-0599", value:TRUE);
}
