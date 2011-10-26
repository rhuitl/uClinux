#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12347);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2002-1393");

 name["english"] = "RHSA-2003-003: arts";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  A security issue has been found in KDE. This errata provides updates which
  resolve these issues.

  KDE is a graphical desktop environment for the X Window System.

  KDE fails in multiple places to properly quote URLs and filenames
  before passing them to a command shell. This could allow remote
  attackers to execute arbitrary commands through carefully crafted URLs,
  filenames, or email addresses.

  Users of KDE are advised to install the updated packages which contain
  backported patches to correct this issue.

  Please note that for the Itanium (IA64) architecture only, this update also
  fixes several other vulnerabilities. Details concerning these
  vulnerabilities can be found in advisory RHSA-2002:221 and correspond to
  CVE names CVE-2002-0970, CVE-2002-1151, CVE-2002-1247, and CVE-2002-1306.




Solution : http://rhn.redhat.com/errata/RHSA-2003-003.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the arts packages";
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
if ( rpm_check( reference:"arts-2.2.2-6", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdebase-2.2.2-6", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdebase-devel-2.2.2-6", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdegames-2.2.2-2", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdegraphics-2.2.2-3", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdegraphics-devel-2.2.2-3", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdelibs-2.2.2-6", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdelibs-devel-2.2.2-6", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdelibs-sound-2.2.2-6", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdelibs-sound-devel-2.2.2-6", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdemultimedia-2.2.2-4", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdemultimedia-devel-2.2.2-4", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdenetwork-2.2.2-3", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdenetwork-ppp-2.2.2-3", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdepim-2.2.2-4", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdepim-cellphone-2.2.2-4", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdepim-devel-2.2.2-4", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdepim-pilot-2.2.2-4", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdesdk-2.2.2-2", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdesdk-devel-2.2.2-2", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdeutils-2.2.2-2", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"arts-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2002-1393", value:TRUE);
}

set_kb_item(name:"RHSA-2003-003", value:TRUE);
