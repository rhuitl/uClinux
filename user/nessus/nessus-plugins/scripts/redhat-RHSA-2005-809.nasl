#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20105);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2005-3184", "CVE-2005-3241", "CVE-2005-3242", "CVE-2005-3243", "CVE-2005-3244", "CVE-2005-3245", "CVE-2005-3246", "CVE-2005-3247", "CVE-2005-3248", "CVE-2005-3249");

 name["english"] = "RHSA-2005-809: ethereal";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated Ethereal packages that fix various security vulnerabilities are now
  available.

  This update has been rated as having moderate security impact by the Red Hat
  Security Response Team.

  The ethereal package is a program for monitoring network traffic.

  A number of security flaws have been discovered in Ethereal. On a system
  where Ethereal is running, a remote attacker could send malicious packets
  to trigger these flaws and cause Ethereal to crash or potentially execute
  arbitrary code. The Common Vulnerabilities and Exposures project
  has assigned the names CVE-2005-3241, CVE-2005-3242, CVE-2005-3243,
  CVE-2005-3244, CVE-2005-3245, CVE-2005-3246, CVE-2005-3247, CVE-2005-3248,
  CVE-2005-3249, and CVE-2005-3184 to these issues.

  Users of ethereal should upgrade to these updated packages, which contain
  version 0.10.13 and are not vulnerable to these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2005-809.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the ethereal packages";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Red Hat Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"ethereal-0.10.13-1.AS21.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ethereal-gnome-0.10.13-1.AS21.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ethereal-0.10.13-1.EL3.1", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ethereal-gnome-0.10.13-1.EL3.1", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ethereal-0.10.13-1.EL4.1", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ethereal-gnome-0.10.13-1.EL4.1", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"ethereal-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2005-3184", value:TRUE);
 set_kb_item(name:"CVE-2005-3241", value:TRUE);
 set_kb_item(name:"CVE-2005-3242", value:TRUE);
 set_kb_item(name:"CVE-2005-3243", value:TRUE);
 set_kb_item(name:"CVE-2005-3244", value:TRUE);
 set_kb_item(name:"CVE-2005-3245", value:TRUE);
 set_kb_item(name:"CVE-2005-3246", value:TRUE);
 set_kb_item(name:"CVE-2005-3247", value:TRUE);
 set_kb_item(name:"CVE-2005-3248", value:TRUE);
 set_kb_item(name:"CVE-2005-3249", value:TRUE);
}
if ( rpm_exists(rpm:"ethereal-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2005-3184", value:TRUE);
 set_kb_item(name:"CVE-2005-3241", value:TRUE);
 set_kb_item(name:"CVE-2005-3242", value:TRUE);
 set_kb_item(name:"CVE-2005-3243", value:TRUE);
 set_kb_item(name:"CVE-2005-3244", value:TRUE);
 set_kb_item(name:"CVE-2005-3245", value:TRUE);
 set_kb_item(name:"CVE-2005-3246", value:TRUE);
 set_kb_item(name:"CVE-2005-3247", value:TRUE);
 set_kb_item(name:"CVE-2005-3248", value:TRUE);
 set_kb_item(name:"CVE-2005-3249", value:TRUE);
}
if ( rpm_exists(rpm:"ethereal-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2005-3184", value:TRUE);
 set_kb_item(name:"CVE-2005-3241", value:TRUE);
 set_kb_item(name:"CVE-2005-3242", value:TRUE);
 set_kb_item(name:"CVE-2005-3243", value:TRUE);
 set_kb_item(name:"CVE-2005-3244", value:TRUE);
 set_kb_item(name:"CVE-2005-3245", value:TRUE);
 set_kb_item(name:"CVE-2005-3246", value:TRUE);
 set_kb_item(name:"CVE-2005-3247", value:TRUE);
 set_kb_item(name:"CVE-2005-3248", value:TRUE);
 set_kb_item(name:"CVE-2005-3249", value:TRUE);
}

set_kb_item(name:"RHSA-2005-809", value:TRUE);
