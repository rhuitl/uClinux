#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2005:014
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(17300);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-0455", "CVE-2005-0611");
 
 name["english"] = "SUSE-SA:2005:014: RealPlayer";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2005:014 (RealPlayer).


Two security problems were found in the media player RealPlayer:

- CVE-2005-0455: A buffer overflow in the handling of .smil files.
- CVE-2005-0611: A buffer overflow in the handling of .wav files.

Both buffer overflows can be exploited remotely by providing URLs
opened by RealPlayer.

More informations can be found on this URL:
http://service.real.com/help/faq/security/050224_player/EN/

This updates fixes the problems.



Solution : http://www.suse.de/security/advisories/2005_14_realplayer.html
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the RealPlayer package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "SuSE Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"RealPlayer-10.0.3-0.1", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"RealPlayer-", release:"SUSE9.2") )
{
 set_kb_item(name:"CVE-2005-0455", value:TRUE);
 set_kb_item(name:"CVE-2005-0611", value:TRUE);
}
