#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12490);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2004-0233");

 name["english"] = "RHSA-2004-174: utempter";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  An updated utempter package that fixes a potential symlink vulnerability is
  now available.

  Utempter is a utility that allows terminal applications such as xterm and
  screen to update utmp and wtmp without requiring root privileges.

  Steve Grubb discovered a flaw in Utempter which allowed device names
  containing directory traversal sequences such as \'/../\'. In combination
  with an application that trusts the utmp or wtmp files, this could allow a
  local attacker the ability to overwrite privileged files using a symlink.

  Users should upgrade to this new version of utempter, which fixes this
  vulnerability.




Solution : http://rhn.redhat.com/errata/RHSA-2004-174.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the utempter packages";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Red Hat Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"utempter-0.5.5-1.2.1EL.0", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"utempter-0.5.5-1.3EL.0", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"utempter-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2004-0233", value:TRUE);
}
if ( rpm_exists(rpm:"utempter-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2004-0233", value:TRUE);
}

set_kb_item(name:"RHSA-2004-174", value:TRUE);
