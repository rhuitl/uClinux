#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2004:025
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14264);
 script_bugtraq_id(10865);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2004-0500");
 
 name["english"] = "SUSE-SA:2004:025: gaim";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2004:025 (gaim).


Gaim is an instant messaging client which supports a wide range of
protocols.

Sebastian Krahmer of the SuSE Security Team discovered various remotely
exploitable buffer overflows in the MSN-protocol parsing functions during
a code review of the MSN protocol handling code.

Remote attackers can execute arbitrary code as the user running the gaim
client.

The vulnerable code exists in SUSE Linux 9.1 only.

Solution : http://www.suse.de/security/2004_25_gaim.html

Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the gaim package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "SuSE Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"gaim-0.75-79.2", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"gaim-", release:"SUSE9.1") )
{
 set_kb_item(name:"CVE-2004-0500", value:TRUE);
}
