#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19713);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2004-2479", "CVE-2005-2794", "CVE-2005-2796");

 name["english"] = "RHSA-2005-766: squid";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  An updated Squid package that fixes security issues is now available.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  Squid is a full-featured Web proxy cache.

  A bug was found in the way Squid displays error messages. A remote attacker
  could submit a request containing an invalid hostname which would result in
  Squid displaying a previously used error message. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CVE-2004-2479 to this issue.

  Two denial of service bugs were found in the way Squid handles malformed
  requests. A remote attacker could submit a specially crafted request to
  Squid that would cause the server to crash. The Common Vulnerabilities and
  Exposures project (cve.mitre.org) has assigned the names CVE-2005-2794 and
  CVE-2005-2796 to these issues.

  Please note that CVE-2005-2796 does not affect Red Hat Enterprise Linux 2.1

  Users of Squid should upgrade to this updated package that contains
  backported patches, and is not vulnerable to these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2005-766.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the squid packages";
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
if ( rpm_check( reference:"squid-2.4.STABLE7-1.21as.10", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"squid-2.5.STABLE3-6.3E.14", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"squid-2.5.STABLE6-3.4E.11", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"squid-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2004-2479", value:TRUE);
 set_kb_item(name:"CVE-2005-2794", value:TRUE);
 set_kb_item(name:"CVE-2005-2796", value:TRUE);
}
if ( rpm_exists(rpm:"squid-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2004-2479", value:TRUE);
 set_kb_item(name:"CVE-2005-2794", value:TRUE);
 set_kb_item(name:"CVE-2005-2796", value:TRUE);
}
if ( rpm_exists(rpm:"squid-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2004-2479", value:TRUE);
 set_kb_item(name:"CVE-2005-2794", value:TRUE);
 set_kb_item(name:"CVE-2005-2796", value:TRUE);
}

set_kb_item(name:"RHSA-2005-766", value:TRUE);
