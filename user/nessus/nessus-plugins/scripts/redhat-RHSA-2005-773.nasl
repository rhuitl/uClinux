#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19714);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-2700");

 name["english"] = "RHSA-2005-773: mod_ssl";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  An updated mod_ssl package for Apache that corrects a security issue is now
  available.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  The mod_ssl module provides strong cryptography for the Apache Web
  server via the Secure Sockets Layer (SSL) and Transport Layer Security
  (TLS) protocols.

  A flaw was discovered in mod_ssl\'s handling of the "SSLVerifyClient"
  directive. This flaw occurs if a virtual host is configured
  using "SSLVerifyClient optional" and a directive "SSLVerifyClient
  required" is set for a specific location. For servers configured in this
  fashion, an attacker may be able to access resources that should otherwise
  be protected, by not supplying a client certificate when connecting. The
  Common Vulnerabilities and Exposures project assigned the name
  CVE-2005-2700 to this issue.

  Users of mod_ssl should upgrade to this updated package, which contains a
  backported patch to correct this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2005-773.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the mod_ssl packages";
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
if ( rpm_check( reference:"mod_ssl-2.8.12-8", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"mod_ssl-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2005-2700", value:TRUE);
}

set_kb_item(name:"RHSA-2005-773", value:TRUE);
