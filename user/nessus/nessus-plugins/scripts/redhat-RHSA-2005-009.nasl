#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16366);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2004-1158", "CVE-2004-1165", "CVE-2005-0078");

 name["english"] = "RHSA-2005-009: arts";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated kdelib and kdebase packages that resolve several security issues
  are now available.

  The kdelibs packages include libraries for the K Desktop Environment. The
  kdebase packages include core applications for the K Desktop Environment.

  Secunia Research discovered a window injection spoofing vulnerability
  affecting the Konqueror web browser. This issue could allow a malicious
  website to show arbitrary content in a different browser window. The Common
  Vulnerabilities and Exposures project has assigned the name CVE-2004-1158
  to this issue.

  A bug was discovered in the way kioslave handles URL-encoded newline (%0a)
  characters before the FTP command. It is possible that a specially crafted
  URL could be used to execute any ftp command on a remote server, or
  potentially send unsolicited email. The Common Vulnerabilities and
  Exposures project has assigned the name CVE-2004-1165 to this issue.

  A bug was discovered that can crash KDE screensaver under certain local
  circumstances. This could allow an attacker with physical access to the
  workstation to take over a locked desktop session. Please note that this
  issue only affects Red Hat Enterprise Linux 2.1. The Common Vulnerabilities
  and Exposures project has assigned the name CVE-2005-0078 to this issue.

  All users of KDE are advised to upgrade to this updated packages, which
  contain backported patches to correct these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2005-009.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the arts packages";
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
if ( rpm_check( reference:"arts-2.2.2-15", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdebase-2.2.2-15", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdebase-devel-2.2.2-15", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdelibs-2.2.2-15", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdelibs-devel-2.2.2-15", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdelibs-sound-2.2.2-15", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdelibs-sound-devel-2.2.2-15", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdebase-3.1.3-5.8", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdebase-devel-3.1.3-5.8", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdelibs-3.1.3-6.9", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdelibs-devel-3.1.3-6.9", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"arts-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2004-1158", value:TRUE);
 set_kb_item(name:"CVE-2004-1165", value:TRUE);
 set_kb_item(name:"CVE-2005-0078", value:TRUE);
}
if ( rpm_exists(rpm:"arts-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2004-1158", value:TRUE);
 set_kb_item(name:"CVE-2004-1165", value:TRUE);
 set_kb_item(name:"CVE-2005-0078", value:TRUE);
}

set_kb_item(name:"RHSA-2005-009", value:TRUE);
