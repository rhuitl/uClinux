#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(17264);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-0446");

 name["english"] = "RHSA-2005-173: squid";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated squid packages that fix a denial of service issue are now
  available.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team

  Squid is a full-featured Web proxy cache.

  A bug was found in the way Squid handles FQDN lookups. It was possible
  to crash the Squid server by sending a carefully crafted DNS response to
  an FQDN lookup. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CVE-2005-0446 to this issue.

  Users of squid should upgrade to this updated package, which contains a
  backported patch, and is not vulnerable to this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2005-173.html
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
if ( rpm_check( reference:"squid-2.4.STABLE7-1.21as.5", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"squid-2.5.STABLE3-6.3E.8", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"squid-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2005-0446", value:TRUE);
}
if ( rpm_exists(rpm:"squid-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2005-0446", value:TRUE);
}

set_kb_item(name:"RHSA-2005-173", value:TRUE);
