#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14211);
 script_version ("$Revision: 1.8 $");
 script_cve_id("CVE-2004-0494");

 name["english"] = "RHSA-2004-373: gnome";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated GNOME VFS packages that remove potential extfs-related
  vulnerabilities are now available.

  GNOME VFS is the GNOME virtual file system. It provides a modular
  architecture and ships with several modules that implement support for file
  systems, HTTP, FTP, and others. The extfs backends make it possible to
  implement file systems for GNOME VFS using scripts.

  Flaws have been found in several of the GNOME VFS extfs backend scripts.
  Red Hat Enterprise Linux ships with vulnerable scripts, but they are not
  used by default. An attacker who is able to influence a user to open a
  specially-crafted URI using gnome-vfs could perform actions as that user.
  The Common Vulnerabilities and Exposures project (cve.mitre.org) has
  assigned the name CVE-2004-0494 to this issue.

  Users of Red Hat Enterprise Linux should upgrade to these updated packages,
  which remove these unused scripts.




Solution : http://rhn.redhat.com/errata/RHSA-2004-373.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the gnome packages";
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
if ( rpm_check( reference:"gnome-vfs-1.0.1-18.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gnome-vfs-devel-1.0.1-18.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gnome-vfs2-2.2.5-2E.1", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gnome-vfs2-devel-2.2.5-2E.1", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"gnome-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2004-0494", value:TRUE);
}
if ( rpm_exists(rpm:"gnome-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2004-0494", value:TRUE);
}

set_kb_item(name:"RHSA-2004-373", value:TRUE);
