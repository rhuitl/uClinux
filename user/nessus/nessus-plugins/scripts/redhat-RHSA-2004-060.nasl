#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12465);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2004-0083", "CVE-2004-0084", "CVE-2004-0106");

 name["english"] = "RHSA-2004-060: XFree";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated XFree86 packages that fix a privilege escalation vulnerability are
  now available.

  XFree86 is an implementation of the X Window System, providing the core
  graphical user interface and video drivers.

  iDefense discovered two buffer overflows in the parsing of the \'font.alias\'
  file. A local attacker could exploit this vulnerability by creating a
  carefully-crafted file and gaining root privileges.
  The Common Vulnerabilities and Exposures project (cve.mitre.org) has
  assigned the names CVE-2004-0083 and CVE-2004-0084 to these issues.

  Additionally David Dawes discovered additional flaws in reading font files.
  The Common Vulnerabilities and Exposures project (cve.mitre.org) has
  assigned the name CVE-2004-0106 to these issues.

  All users of XFree86 are advised to upgrade to these erratum packages,
  which contain a backported fix and are not vulnerable to these issues.

  Red Hat would like to thank David Dawes from XFree86 for the patches and
  notification of these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2004-060.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the XFree packages";
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
if ( rpm_check( reference:"XFree86-100dpi-fonts-4.1.0-56.EL", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-4.1.0-56.EL", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-75dpi-fonts-4.1.0-56.EL", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-cyrillic-fonts-4.1.0-56.EL", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-devel-4.1.0-56.EL", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-doc-4.1.0-56.EL", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-ISO8859-15-100dpi-fonts-4.1.0-56.EL", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-ISO8859-15-75dpi-fonts-4.1.0-56.EL", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-ISO8859-2-100dpi-fonts-4.1.0-56.EL", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-ISO8859-2-75dpi-fonts-4.1.0-56.EL", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-ISO8859-9-100dpi-fonts-4.1.0-56.EL", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-ISO8859-9-75dpi-fonts-4.1.0-56.EL", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-libs-4.1.0-56.EL", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-tools-4.1.0-56.EL", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-twm-4.1.0-56.EL", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-xdm-4.1.0-56.EL", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-xf86cfg-4.1.0-56.EL", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-xfs-4.1.0-56.EL", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-Xnest-4.1.0-56.EL", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-Xvfb-4.1.0-56.EL", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"XFree-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2004-0083", value:TRUE);
 set_kb_item(name:"CVE-2004-0084", value:TRUE);
 set_kb_item(name:"CVE-2004-0106", value:TRUE);
}

set_kb_item(name:"RHSA-2004-060", value:TRUE);
