#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18471);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-0718", "CVE-2005-1519", "CVE-1999-0710");

 name["english"] = "RHSA-2005-489: squid";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  An updated squid package that fixes several security issues is now
  available.

  This update has been rated as having low security impact by the Red Hat
  Security Response Team.

  Squid is a full-featured Web proxy cache.

  A bug was found in the way Squid handles PUT and POST requests. It is
  possible for an authorised remote user to cause a failed PUT or POST
  request which can cause Squid to crash. The Common Vulnerabilities and
  Exposures project (cve.mitre.org) has assigned the name CVE-2005-0718 to
  this issue.

  A bug was found in the way Squid handles access to the cachemgr.cgi script.
  It is possible for an authorised remote user to bypass access control
  lists with this flaw. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CVE-1999-0710 to this issue.

  A bug was found in the way Squid handles DNS replies. If the port Squid
  uses for DNS requests is not protected by a firewall, it is possible for a
  remote attacker to spoof DNS replies, possibly redirecting a user to
  spoofed or malicious content. The Common Vulnerabilities and Exposures
  project (cve.mitre.org) has assigned the name CVE-2005-1519 to this issue.

  Additionally, this update fixes the following bugs:
  - squid fails in the unpacking of squid-2.4.STABLE7-1.21as.5.src.rpm

  Users of Squid should upgrade to this updated package, which contains
  backported patches to correct these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2005-489.html
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
if ( rpm_check( reference:"squid-2.4.STABLE7-1.21as.8", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"squid-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2005-0718", value:TRUE);
 set_kb_item(name:"CVE-2005-1519", value:TRUE);
 set_kb_item(name:"CVE-1999-0710", value:TRUE);
}

set_kb_item(name:"RHSA-2005-489", value:TRUE);
