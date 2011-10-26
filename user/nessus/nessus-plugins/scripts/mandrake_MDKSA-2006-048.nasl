#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2006:048
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(21002);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2006-0579");
 
 name["english"] = "MDKSA-2006:048: mplayer";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2006:048 (mplayer).



Multiple integer overflows in (1) the new_demux_packet function in demuxer.h
and (2) the demux_asf_read_packet function in demux_asf.c in MPlayer
1.0pre7try2 and earlier allow remote attackers to execute arbitrary code via an
ASF file with a large packet length value. The updated packages have been
patched to prevent this problem.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2006:048
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the mplayer package";
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
if ( rpm_check( reference:"libdha1.0-1.0-1.pre7.12.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libpostproc0-1.0-1.pre7.12.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libpostproc0-devel-1.0-1.pre7.12.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mencoder-1.0-1.pre7.12.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mplayer-1.0-1.pre7.12.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mplayer-gui-1.0-1.pre7.12.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"mplayer-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2006-0579", value:TRUE);
}
