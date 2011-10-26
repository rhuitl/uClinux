#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19652);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-1038");
 
 name["english"] = "Fedora Core 3 2005-320: vixie-cron";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2005-320 (vixie-cron).

The vixie-cron package contains the Vixie version of cron.  Cron is a
standard UNIX daemon that runs specified programs at scheduled times.
Vixie cron adds better security and more powerful configuration
options to the standard version of cron.


o Fixes security vulnerability CVE-2005-1038
( [14]http://www.securityfocus.com/archive/1/395093 )

o Makes filename and command line length constraints
correspond to system limits

o Improved PAM support



Solution : Get the newest Fedora Updates
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the vixie-cron package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Fedora Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"vixie-cron-4.1-33_FC3", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"vixie-cron-", release:"FC3") )
{
 set_kb_item(name:"CVE-2005-1038", value:TRUE);
}
