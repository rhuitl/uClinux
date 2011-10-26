#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2006:015
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(21136);
 script_version ("$Revision: 1.1 $");
 
 name["english"] = "SUSE-SA:2006:015: flash-player";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2006:015 (flash-player).


A critical security vulnerability has been identified in the Adobe
Macromedia Flash Player that allows an attacker who successfully
exploits these vulnerabilities to take control of the application
running the flash player.

A malicious SWF must be loaded in the Flash Player by the user for
an attacker to exploit these vulnerabilities.

This issue is tracked by the Mitre CVE ID CVE-2006-0024.


Solution : http://www.suse.de/security/advisories/2006_15_flashplayer.html
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the flash-player package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 family["english"] = "SuSE Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"flash-player-7.0.63.0-1.1", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"flash-player-7.0.63.0-1.2", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"flash-player-7.0.63.0-1.1", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"flash-player-7.0.63.0-1.1", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
