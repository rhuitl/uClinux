#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18473);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-1686");

 name["english"] = "RHSA-2005-499: gedit";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  An updated gedit package that fixes a file name format string vulnerability
  is now available.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team

  gEdit is a small text editor designed specifically for the GNOME GUI
  desktop.

  A file name format string vulnerability has been discovered in gEdit. It is
  possible for an attacker to create a file with a carefully crafted name
  which, when the file is opened, executes arbitrary instructions on a
  victim\'s machine. Although it is unlikely that a user would manually open a
  file with such a carefully crafted file name, a user could, for example, be
  tricked into opening such a file from within an email client. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CVE-2005-1686 to this issue.

  Users of gEdit should upgrade to this updated package, which contains a
  backported patch to correct this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2005-499.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the gedit packages";
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
if ( rpm_check( reference:"gedit-2.2.2-4.rhel3", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gedit-2.8.1-4", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gedit-devel-2.8.1-4", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"gedit-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2005-1686", value:TRUE);
}
if ( rpm_exists(rpm:"gedit-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2005-1686", value:TRUE);
}

set_kb_item(name:"RHSA-2005-499", value:TRUE);
