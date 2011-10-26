#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12341);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2002-1355", "CVE-2002-1356");

 name["english"] = "RHSA-2002-291: ethereal";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated Ethereal packages are available which fix various security issues.

  [Updated 06 Feb 2003]
  Added fixed packages for Advanced Workstation 2.1

  Ethereal is a package designed for monitoring network traffic on your
  system. Several security issues have been found in the Ethereal packages
  distributed with Red Hat Linux Advanced Server 2.1.

  Multiple errors involving signed integers in the BGP dissector in Ethereal
  0.9.7 and earlier allow remote attackers to cause a denial of service
  (infinite loop) via malformed messages. This problem was discovered by
  Silvio Cesare. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CVE-2002-1355 to this issue.

  Ethereal 0.9.7 and earlier allows remote attackers to cause a denial
  of service (crash) and possibly execute arbitrary code via malformed
  packets to the LMP, PPP, or TDS dissectors. The Common Vulnerabilities and
  Exposures project (cve.mitre.org) has assigned the name CVE-2002-1356 to
  this issue.

  Users of Ethereal should update to the errata packages containing Ethereal
  version 0.9.8 which is not vulnerable to these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2002-291.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the ethereal packages";
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
if ( rpm_check( reference:"ethereal-0.9.8-0.AS21.0", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ethereal-gnome-0.9.8-0.AS21.0", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"ethereal-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2002-1355", value:TRUE);
 set_kb_item(name:"CVE-2002-1356", value:TRUE);
}

set_kb_item(name:"RHSA-2002-291", value:TRUE);
