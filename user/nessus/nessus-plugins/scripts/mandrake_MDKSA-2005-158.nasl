#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:158
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19913);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2005-2718");
 
 name["english"] = "MDKSA-2005:158: mplayer";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:158 (mplayer).



Buffer overflow in ad_pcm.c in MPlayer 1.0pre7 and earlier allows remote
attackers to execute arbitrary code via a video file with an audio header
containing a large value in a strf chunk.

The updated packages have been patched to correct this problem.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:158
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the mplayer package";
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
if ( rpm_check( reference:"libdha1.0-1.0-0.pre5.8.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libpostproc0-1.0-0.pre5.8.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libpostproc0-devel-1.0-0.pre5.8.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mencoder-1.0-0.pre5.8.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mplayer-1.0-0.pre5.8.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mplayer-gui-1.0-0.pre5.8.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libdha1.0-1.0-0.pre6.8.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libpostproc0-1.0-0.pre6.8.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libpostproc0-devel-1.0-0.pre6.8.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mencoder-1.0-0.pre6.8.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mplayer-1.0-0.pre6.8.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mplayer-gui-1.0-0.pre6.8.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"mplayer-", release:"MDK10.1")
 || rpm_exists(rpm:"mplayer-", release:"MDK10.2") )
{
 set_kb_item(name:"CVE-2005-2718", value:TRUE);
}
