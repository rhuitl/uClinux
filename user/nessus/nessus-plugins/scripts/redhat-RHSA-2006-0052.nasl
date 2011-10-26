#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(21031);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2005-2917");

 name["english"] = "RHSA-2006-0052: squid";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  An updated squid package that fixes a security vulnerability as well as
  several issues is now available.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  Squid is a high-performance proxy caching server for Web clients,
  supporting FTP, gopher, and HTTP data objects.

  A denial of service flaw was found in the way squid processes certain NTLM
  authentication requests. It is possible for a remote attacker to crash the
  Squid server by sending a specially crafted NTLM authentication request.
  The Common Vulnerabilities and Exposures project (cve.mitre.org) assigned
  the name CVE-2005-2917 to this issue.

  The following issues have also been fixed in this update:

  * An error introduced in squid-2.5.STABLE6-3.4E.12 can crash Squid when a
  user visits a site that has a bit longer DNS record.

  * An error introduced in the old package prevented Squid from returning
  correct information about large file systems. The new package is compiled
  with the IDENT lookup support so that users who want to use it do not
  have to recompile it.

  * Some authentication helpers needed SETUID rights but did not have them.
  If administrators wanted to use cache administrator, they had to change
  the SETUID bit manually. The updated package sets this bit so the new
  package can be updated without manual intervention from administrators.

  * Squid could not handle a reply from an HTTP server when the reply began
  with the new-line character.

  * An issue was discovered when a reply from an HTTP server was not
  HTTP 1.0 or 1.1 compliant.

  * The updated package keeps user-defined error pages when the package
  is updated and it adds new ones.

  All users of squid should upgrade to this updated package, which resolves
  these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2006-0052.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the squid packages";
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
if ( rpm_check( reference:"squid-2.5.STABLE6-3.4E.12", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"squid-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2005-2917", value:TRUE);
}

set_kb_item(name:"RHSA-2006-0052", value:TRUE);
