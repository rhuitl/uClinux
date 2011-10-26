#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12482);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2004-0176", "CVE-2004-0365", "CVE-2004-0367");

 name["english"] = "RHSA-2004-136: ethereal";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated Ethereal packages that fix various security vulnerabilities are now
  available.

  Ethereal is a program for monitoring network traffic.

  Stefan Esser reported that Ethereal versions 0.10.1 and earlier contain
  stack overflows in the IGRP, PGM, Metflow, ISUP, TCAP, or IGAP dissectors.
  On a system where Ethereal is being run a remote attacker could send
  malicious packets that could cause Ethereal to crash or execute arbitrary
  code. The Common Vulnerabilities and Exposures project (cve.mitre.org) has
  assigned the name CVE-2004-0176 to this issue.

  Jonathan Heussser discovered that a carefully-crafted RADIUS packet could
  cause a crash. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CVE-2004-0365 to this issue.

  Ethereal 0.8.13 to 0.10.2 allows remote attackers to cause a denial of
  service (crash) via a zero-length Presentation protocol selector. The
  Common Vulnerabilities and Exposures project (cve.mitre.org) has assigned
  the name CVE-2004-0367 to this issue.

  Users of Ethereal should upgrade to these updated packages, which contain
  a version of Ethereal that is not vulnerable to these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2004-136.html
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
if ( rpm_check( reference:"ethereal-0.10.3-0.AS21.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ethereal-gnome-0.10.3-0.AS21.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ethereal-0.10.3-0.30E.1", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ethereal-gnome-0.10.3-0.30E.1", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"ethereal-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2004-0176", value:TRUE);
 set_kb_item(name:"CVE-2004-0365", value:TRUE);
 set_kb_item(name:"CVE-2004-0367", value:TRUE);
}
if ( rpm_exists(rpm:"ethereal-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2004-0176", value:TRUE);
 set_kb_item(name:"CVE-2004-0365", value:TRUE);
 set_kb_item(name:"CVE-2004-0367", value:TRUE);
}

set_kb_item(name:"RHSA-2004-136", value:TRUE);
