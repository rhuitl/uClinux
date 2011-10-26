#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2004:157
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16038);
 script_version ("$Revision: 1.2 $");
 
 name["english"] = "MDKSA-2004:157: mplayer";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2004:157 (mplayer).



A number of vulnerabilities were discovered in the MPlayer program by iDEFENSE,
Ariel Berkman, and the MPlayer development team. These vulnerabilities include
potential heap overflows in Real RTSP and pnm streaming code, stack overflows
in MMST streaming code, and multiple buffer overflows in the BMP demuxer and
mp3lib code.

The updated packages have been patched to prevent these problems.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:157
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
if ( rpm_check( reference:"libdha0.1-1.0-0.pre3.14.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libpostproc0-1.0-0.pre3.14.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libpostproc0-devel-1.0-0.pre3.14.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mencoder-1.0-0.pre3.14.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mplayer-1.0-0.pre3.14.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mplayer-gui-1.0-0.pre3.14.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libdha1.0-1.0-0.pre5.7.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libpostproc0-1.0-0.pre5.7.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libpostproc0-devel-1.0-0.pre5.7.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mencoder-1.0-0.pre5.7.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mplayer-1.0-0.pre5.7.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mplayer-gui-1.0-0.pre5.7.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
