#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:232
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20463);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2005-4048");
 
 name["english"] = "MDKSA-2005:232: gstreamer-ffmpeg";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:232 (gstreamer-ffmpeg).



Simon Kilvington discovered a vulnerability in FFmpeg libavcodec, which can be
exploited by malicious people to cause a DoS (Denial of Service) and
potentially to compromise a user's system. The vulnerability is caused due to a
boundary error in the 'avcodec_default_get_buffer()' function of 'utils.c' in
libavcodec. This can be exploited to cause a heap-based buffer overflow when a
specially-crafted 1x1 '.png' file containing a palette is read.
Gstreamer-ffmpeg is built with a private copy of ffmpeg containing this same
code. The updated packages have been patched to prevent this problem.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:232
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the gstreamer-ffmpeg package";
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
if ( rpm_check( reference:"gstreamer-ffmpeg-0.8.6-1.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"gstreamer-ffmpeg-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2005-4048", value:TRUE);
}
