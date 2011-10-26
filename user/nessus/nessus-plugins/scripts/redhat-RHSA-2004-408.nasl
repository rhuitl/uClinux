#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14698);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2004-0700");

 name["english"] = "RHSA-2004-408: mod_ssl";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  An updated mod_ssl package for Apache that fixes a format string
  vulnerability is now available.

  The mod_ssl module provides strong cryptography for the Apache Web
  server via the Secure Sockets Layer (SSL) and Transport Layer Security
  (TLS) protocols.

  A format string issue was discovered in mod_ssl for Apache 1.3 which can be
  triggered if mod_ssl is configured to allow a client to proxy to remote SSL
  sites. In order to exploit this issue, a user who is authorized to use
  Apache as a proxy would have to attempt to connect to a carefully crafted
  hostname via SSL. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CVE-2004-0700 to this issue.

  Users of mod_ssl should upgrade to this updated package, which contains a
  backported patch to correct this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2004-408.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the mod_ssl packages";
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
if ( rpm_check( reference:"mod_ssl-2.8.12-6", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"mod_ssl-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2004-0700", value:TRUE);
}

set_kb_item(name:"RHSA-2004-408", value:TRUE);
