#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2003:097
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14079);
 script_bugtraq_id(8702);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2003-0835");
 
 name["english"] = "MDKSA-2003:097: mplayer";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2003:097 (mplayer).


A buffer overflow vulnerability was found in MPlayer that is remotely
exploitable. A malicious host can craft a harmful ASX header and trick MPlayer
into executing arbitrary code when it parses that particular header.
The provided packages have been patched to fix the problem.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:097
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the mplayer package";
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
if ( rpm_check( reference:"libdha0.1-0.90-0.rc4.5.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libpostproc0-0.90-0.rc4.5.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libpostproc0-devel-0.90-0.rc4.5.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mencoder-0.90-0.rc4.5.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mplayer-0.90-0.rc4.5.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mplayer-gui-0.90-0.rc4.5.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libdha0.1-0.91-7.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libpostproc0-0.91-7.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libpostproc0-devel-0.91-7.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mencoder-0.91-7.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mplayer-0.91-7.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mplayer-gui-0.91-7.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"mplayer-", release:"MDK9.1")
 || rpm_exists(rpm:"mplayer-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2003-0835", value:TRUE);
}
