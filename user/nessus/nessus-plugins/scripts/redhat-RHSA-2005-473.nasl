#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18390);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-0605");

 name["english"] = "RHSA-2005-473: lesstif";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated lesstif packages that fix flaws in the Xpm library are now
  available for Red Hat Enterprise Linux 2.1.

  This update has been rated as having Moderate security impact by the Red
  Hat Security Response Team.

  LessTif provides libraries which implement the Motif industry standard
  graphical user interface.

  An integer overflow flaw was found in libXpm; a vulnerable version of this
  library is found within LessTif. An attacker could create a malicious XPM
  file that would execute arbitrary code if opened by a victim using an
  application linked to LessTif. The Common Vulnerabilities and Exposures
  project (cve.mitre.org) has assigned the name CVE-2005-0605 to this issue.

  Users of LessTif should upgrade to these updated packages, which contain a
  backported patch to correct this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2005-473.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the lesstif packages";
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
if ( rpm_check( reference:"lesstif-0.93.15-4.AS21.5", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"lesstif-devel-0.93.15-4.AS21.5", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"lesstif-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2005-0605", value:TRUE);
}

set_kb_item(name:"RHSA-2005-473", value:TRUE);
