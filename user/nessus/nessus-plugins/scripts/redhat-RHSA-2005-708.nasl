#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19425);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-2097");

 name["english"] = "RHSA-2005-708: gpdf";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  An updated gpdf package that fixes a security issue is now available for
  Red Hat Enterprise Linux 4.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  The gpdf package is an GNOME based viewer for Portable Document Format
  (PDF) files.

  Marcus Meissner reported a flaw in gpdf. An attacker could construct a
  carefully crafted PDF file that would cause gpdf to consume all available
  disk space in /tmp when opened. The Common Vulnerabilities and Exposures
  project assigned the name CVE-2005-2097 to this issue.

  Note that this issue does not affect the version of gpdf in Red Hat
  Enterprise Linux 3 or 2.1.

  Users of gpdf should upgrade to this updated package, which contains a
  backported patch to resolve this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2005-708.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the gpdf packages";
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
if ( rpm_check( reference:"gpdf-2.8.2-4.4", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"gpdf-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2005-2097", value:TRUE);
}

set_kb_item(name:"RHSA-2005-708", value:TRUE);
