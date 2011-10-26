#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13690);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2004-0233");
 
 name["english"] = "Fedora Core 2 2004-108: utempter";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2004-108 (utempter).

Utempter is a utility which allows some non-privileged programs to
have required root access without compromising system
security. Utempter accomplishes this feat by acting as a buffer
between root and the programs.

Update Information:

Topic:
An updated utempter package that fixes a potential symlink vulnerability is
now available.

Problem Description:
Utempter is a utility that allows terminal applications such as xterm and
screen to update utmp and wtmp without requiring root privileges.

Steve Grubb discovered a flaw in Utempter which allowed device names
containing directory traversal sequences such as '/../'. In combination
with an application that trusts the utmp or wtmp files, this could allow a
local attacker the ability to overwrite privileged files using a symlink.

Users should upgrade to this new version of utempter, which fixes this
vulnerability.


Solution : http://www.fedoranews.org/updates/FEDORA-2004-108.shtml
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the utempter package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Fedora Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"utempter-0.5.5-3.FC1.0", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"utempter-debuginfo-0.5.5-3.FC1.0", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"utempter-", release:"FC2") )
{
 set_kb_item(name:"CVE-2004-0233", value:TRUE);
}
