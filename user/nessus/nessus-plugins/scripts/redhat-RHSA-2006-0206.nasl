#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20900);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2006-0301");

 name["english"] = "RHSA-2006-0206: kdegraphics";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated kdegraphics packages that resolve a security issue in kpdf are now
  available.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  The kdegraphics packages contain applications for the K Desktop Environment
  including kpdf, a pdf file viewer.

  A heap based buffer overflow bug was discovered in kpdf. An attacker could
  construct a carefully crafted PDF file that could cause kpdf to crash or
  possibly execute arbitrary code when opened. The Common Vulnerabilities and
  Exposures project assigned the name CVE-2006-0301 to this issue.

  Users of kpdf should upgrade to these updated packages, which contain a
  backported patch to resolve this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2006-0206.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the kdegraphics packages";
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
if ( rpm_check( reference:"kdegraphics-3.3.1-3.7", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdegraphics-devel-3.3.1-3.7", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"kdegraphics-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2006-0301", value:TRUE);
}

set_kb_item(name:"RHSA-2006-0206", value:TRUE);
