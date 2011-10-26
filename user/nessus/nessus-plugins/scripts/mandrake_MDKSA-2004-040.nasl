#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2004:040
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14139);
 script_bugtraq_id(10244);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2004-0421");
 
 name["english"] = "MDKSA-2004:040: libpng";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2004:040 (libpng).


Steve Grubb discovered that libpng would access memory that is out of bounds
when creating an error message. The impact of this bug is not clear, but it
could lead to a core dump in a program using libpng, or could result in a DoS
(Denial of Service) condition in a daemon that uses libpng to process PNG
imagaes.
The updated packages are patched to correct the vulnerability.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:040
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
if ( rpm_check( reference:"libpng3-1.2.5-10.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libpng3-devel-1.2.5-10.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libpng3-1.2.5-2.2.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libpng3-devel-1.2.5-2.2.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libpng3-static-devel-1.2.5-2.2.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libpng3-1.2.5-7.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libpng3-devel-1.2.5-7.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libpng3-static-devel-1.2.5-7.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"libpng-", release:"MDK10.0")
 || rpm_exists(rpm:"libpng-", release:"MDK9.1")
 || rpm_exists(rpm:"libpng-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2004-0421", value:TRUE);
}
