#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12433);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2003-0925", "CVE-2003-0926", "CVE-2003-0927");

 name["english"] = "RHSA-2003-324: ethereal";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated Ethereal packages that fix a number of exploitable security issues
  are now available.

  Ethereal is a program for monitoring network traffic.

  A number of security issues affect Ethereal. By exploiting these issues,
  it may be possible to make Ethereal crash or run arbitrary code by
  injecting a purposefully-malformed packet onto the wire or by convincing
  someone to read a malformed packet trace file.

  A buffer overflow in Ethereal 0.9.15 and earlier allows remote attackers
  to cause a denial of service and possibly execute arbitrary code via a
  malformed GTP MSISDN string. The Common Vulnerabilities and Exposures
  project (cve.mitre.org) has assigned the name CVE-2003-0925 to
  this issue.

  Ethereal 0.9.15 and earlier allows remote attackers to cause a denial of
  service (crash) via certain malformed ISAKMP or MEGACO packets. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CVE-2003-0926 to this issue.

  A heap-based buffer overflow in Ethereal 0.9.15 and earlier allows
  remote attackers to cause a denial of service (crash) and possibly
  execute arbitrary code via the SOCKS dissector. The Common Vulnerabilities
  and Exposures project (cve.mitre.org) has assigned the name CVE-2003-0927
  to this issue.

  Users of Ethereal should update to these erratum packages containing
  Ethereal version 0.9.16, which is not vulnerable to these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2003-324.html
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
if ( rpm_check( reference:"ethereal-0.9.16-0.AS21.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ethereal-gnome-0.9.16-0.AS21.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ethereal-0.9.16-0.30E.1", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ethereal-gnome-0.9.16-0.30E.1", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"ethereal-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2003-0925", value:TRUE);
 set_kb_item(name:"CVE-2003-0926", value:TRUE);
 set_kb_item(name:"CVE-2003-0927", value:TRUE);
}
if ( rpm_exists(rpm:"ethereal-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2003-0925", value:TRUE);
 set_kb_item(name:"CVE-2003-0926", value:TRUE);
 set_kb_item(name:"CVE-2003-0927", value:TRUE);
}

set_kb_item(name:"RHSA-2003-324", value:TRUE);
