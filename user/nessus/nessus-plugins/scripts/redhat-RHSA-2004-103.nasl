#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12476);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2004-0111");

 name["english"] = "RHSA-2004-103: gdk";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated gdk-pixbuf packages that fix a crash are now available.

  The gdk-pixbuf package contains an image loading library used with the
  GNOME GUI desktop environment.

  Thomas Kristensen discovered a bitmap file that would cause versions of
  gdk-pixbuf prior to 0.20 to crash. To exploit this flaw, an attacker would
  need to get a victim to open a carefully-crafted BMP file in an application
  that used gdk-pixbuf. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CVE-2004-0111 to this issue.

  Users are advised to upgrade to these updated packages containing
  gdk-pixbuf version 0.22, which is not vulnerable to this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2004-103.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the gdk packages";
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
if ( rpm_check( reference:"gdk-pixbuf-0.22.0-6.0.3", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gdk-pixbuf-devel-0.22.0-6.0.3", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gdk-pixbuf-gnome-0.22.0-6.0.3", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gdk-pixbuf-0.22.0-6.1.1", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gdk-pixbuf-devel-0.22.0-6.1.1", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gdk-pixbuf-gnome-0.22.0-6.1.1", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"gdk-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2004-0111", value:TRUE);
}
if ( rpm_exists(rpm:"gdk-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2004-0111", value:TRUE);
}

set_kb_item(name:"RHSA-2004-103", value:TRUE);
