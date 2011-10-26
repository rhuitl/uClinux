#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:094
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18412);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2005-1195");
 
 name["english"] = "MDKSA-2005:094: xine-lib";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:094 (xine-lib).



Two buffer overflow vulnerabilities were discovered in the MMS and Real RTSP
stream handlers in the Xine libraries. If an attacker can trick a user to
connect to a malicious MMS or RTSP video/audio stream source with any
application using this library, they could crash the client and possibly even
execute arbitrary code with the privileges of the user running the player
program.

The updated packages have been patched to correct these problems.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:094
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the xine-lib package";
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
if ( rpm_check( reference:"libxine1-1-0.rc5.9.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libxine1-devel-1-0.rc5.9.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xine-aa-1-0.rc5.9.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xine-arts-1-0.rc5.9.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xine-dxr3-1-0.rc5.9.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xine-esd-1-0.rc5.9.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xine-flac-1-0.rc5.9.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xine-gnomevfs-1-0.rc5.9.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xine-plugins-1-0.rc5.9.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libxine1-1.0-8.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libxine1-devel-1.0-8.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xine-aa-1.0-8.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xine-arts-1.0-8.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xine-dxr3-1.0-8.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xine-esd-1.0-8.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xine-flac-1.0-8.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xine-gnomevfs-1.0-8.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xine-plugins-1.0-8.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xine-polyp-1.0-8.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xine-smb-1.0-8.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"xine-lib-", release:"MDK10.1")
 || rpm_exists(rpm:"xine-lib-", release:"MDK10.2") )
{
 set_kb_item(name:"CVE-2005-1195", value:TRUE);
}
