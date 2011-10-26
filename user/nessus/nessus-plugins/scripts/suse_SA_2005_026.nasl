#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2005:026
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18112);
 script_version ("$Revision: 1.1 $");
 
 name["english"] = "SUSE-SA:2005:026: RealPlayer";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2005:026 (RealPlayer).


This update fixes a security issue within the RealPlayer media player.

A remote attacker could craft a special .RAM (Real Audio Media) file
which would cause a buffer overflow when played within RealPlayer.

This is the Real Player Update as referenced on this page:

http://service.real.com/help/faq/security/050419_player/EN/


Solution : http://www.suse.de/security/advisories/2005_26_realplayer.html
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
if ( rpm_check( reference:"RealPlayer-10.0.4-1.1", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"RealPlayer-10.0.4-1.1", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
