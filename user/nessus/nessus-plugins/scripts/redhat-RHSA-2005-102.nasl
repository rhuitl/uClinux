#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18441);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-0201");

 name["english"] = "RHSA-2005-102: dbus";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated dbus packages that fix a security issue are now available for
  Red Hat Enterprise Linux 4.

  This update has been rated as having low security impact by the Red Hat
  Security Response Team.

  D-BUS is a system for sending messages between applications. It is
  used both for the systemwide message bus service, and as a
  per-user-login-session messaging facility.

  Dan Reed discovered that a user can send and listen to messages on another
  user\'s per-user session bus if they know the address of the socket. The
  Common Vulnerabilities and Exposures project (cve.mitre.org) has assigned
  the name CVE-2005-0201 to this issue. In Red Hat Enterprise Linux 4, the
  per-user session bus is only used for printing notifications, therefore
  this issue would only allow a local user to examine or send additional
  print notification messages.

  Users of dbus are advised to upgrade to these updated packages,
  which contain backported patches to correct this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2005-102.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the dbus packages";
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
if ( rpm_check( reference:"dbus-0.22-12.EL.2", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"dbus-devel-0.22-12.EL.2", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"dbus-glib-0.22-12.EL.2", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"dbus-python-0.22-12.EL.2", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"dbus-x11-0.22-12.EL.2", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"dbus-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2005-0201", value:TRUE);
}

set_kb_item(name:"RHSA-2005-102", value:TRUE);
