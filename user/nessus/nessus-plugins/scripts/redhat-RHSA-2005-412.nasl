#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18253);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-0605");

 name["english"] = "RHSA-2005-412: openmotif";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated openmotif packages that fix a flaw in the Xpm image library are now
  available.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  OpenMotif provides libraries which implement the Motif industry standard
  graphical user interface.

  An integer overflow flaw was found in libXpm, which is used to decode XPM
  (X PixMap) images. A vulnerable version of this library was
  found within OpenMotif. An attacker could create a carefully crafted XPM
  file which would cause an application to crash or potentially execute
  arbitrary code if opened by a victim. The Common Vulnerabilities and
  Exposures project (cve.mitre.org) has assigned the name CVE-2005-0605 to
  this issue.

  Users of OpenMotif are advised to upgrade to these erratum packages, which
  contains a backported security patch to the embedded libXpm library.




Solution : http://rhn.redhat.com/errata/RHSA-2005-412.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the openmotif packages";
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
if ( rpm_check( reference:"openmotif-2.1.30-13.21AS.5", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openmotif-devel-2.1.30-13.21AS.5", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openmotif-2.2.3-5.RHEL3.2", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openmotif-devel-2.2.3-5.RHEL3.2", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openmotif21-2.1.30-9.RHEL3.6", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openmotif-2.2.3-9.RHEL4.1", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openmotif-devel-2.2.3-9.RHEL4.1", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openmotif21-2.1.30-11.RHEL4.4", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"openmotif-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2005-0605", value:TRUE);
}
if ( rpm_exists(rpm:"openmotif-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2005-0605", value:TRUE);
}
if ( rpm_exists(rpm:"openmotif-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2005-0605", value:TRUE);
}

set_kb_item(name:"RHSA-2005-412", value:TRUE);
