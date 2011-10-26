#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20482);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2005-3624", "CVE-2005-3625", "CVE-2005-3626", "CVE-2005-3627");

 name["english"] = "RHSA-2006-0177: gpdf";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  An updated gpdf package that fixes several security issues is now available
  for Red Hat Enterprise Linux 4.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  gpdf is a GNOME based viewer for Portable Document Format (PDF) files.

  Chris Evans discovered several flaws in the way gpdf processes PDF files.
  An attacker could construct a carefully crafted PDF file that could cause
  gpdf to crash or possibly execute arbitrary code when opened. The Common
  Vulnerabilities and Exposures project assigned the names CVE-2005-3624,
  CVE-2005-3625, CVE-2005-3626, and CVE-2005-3627 to these issues.

  Users of gpdf should upgrade to this updated package, which contains a
  backported patch to resolve these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2006-0177.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the gpdf packages";
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
if ( rpm_check( reference:"gpdf-2.8.2-7.4", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"gpdf-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2005-3624", value:TRUE);
 set_kb_item(name:"CVE-2005-3625", value:TRUE);
 set_kb_item(name:"CVE-2005-3626", value:TRUE);
 set_kb_item(name:"CVE-2005-3627", value:TRUE);
}

set_kb_item(name:"RHSA-2006-0177", value:TRUE);
