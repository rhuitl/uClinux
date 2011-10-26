#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19411);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-2097");

 name["english"] = "RHSA-2005-671: kdegraphics";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated kdegraphics packages that resolve a security issue in kpdf are now
  available.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  The kdegraphics packages contain applications for the K Desktop Environment
  including kpdf, a pdf file viewer.

  A flaw was discovered in kpdf. An attacker could construct a carefully
  crafted PDF file that would cause kpdf to consume all available disk space
  in /tmp when opened. The Common Vulnerabilities and Exposures project
  assigned the name CVE-2005-2097 to this issue.

  Note this issue does not affect Red Hat Enterprise Linux 3 or 2.1.

  Users of kpdf should upgrade to these updated packages, which contains a
  backported patch to resolve this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2005-671.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the kdegraphics packages";
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
if ( rpm_check( reference:"kdegraphics-3.3.1-3.4", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdegraphics-devel-3.3.1-3.4", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"kdegraphics-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2005-2097", value:TRUE);
}

set_kb_item(name:"RHSA-2005-671", value:TRUE);
