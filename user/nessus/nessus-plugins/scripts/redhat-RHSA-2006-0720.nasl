#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(22896);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2006-4811");

 name["english"] = "RHSA-2006-0720: arts";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated kdelibs packages that correct an integer overflow flaw are now
  available.

  This update has been rated as having critical security impact by the Red
  Hat Security Response Team.

  The kdelibs package provides libraries for the K Desktop Environment (KDE).
  Qt is a GUI software toolkit for the X Window System.

  An integer overflow flaw was found in the way Qt handled pixmap images.
  The KDE khtml library uses Qt in such a way that untrusted parameters could
  be passed to Qt, triggering the overflow. An attacker could for example
  create a malicious web page that when viewed by a victim in the Konqueror
  browser would cause Konqueror to crash or possibly execute arbitrary code
  with the privileges of the victim. (CVE-2006-4811)

  Users of KDE should upgrade to these updated packages, which contain a
  backported patch to correct this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2006-0720.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the arts packages";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 family["english"] = "Red Hat Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"arts-2.2.2-21.EL2", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdelibs-2.2.2-21.EL2", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdelibs-devel-2.2.2-21.EL2", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdelibs-sound-2.2.2-21.EL2", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdelibs-sound-devel-2.2.2-21.EL2", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdelibs-3.1.3-6.12", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdelibs-devel-3.1.3-6.12", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdelibs-3.3.1-6.RHEL4", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdelibs-devel-3.3.1-6.RHEL4", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"arts-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2006-4811", value:TRUE);
}
if ( rpm_exists(rpm:"arts-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2006-4811", value:TRUE);
}
if ( rpm_exists(rpm:"arts-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2006-4811", value:TRUE);
}

set_kb_item(name:"RHSA-2006-0720", value:TRUE);
