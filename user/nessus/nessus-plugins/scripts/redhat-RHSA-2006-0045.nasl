#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(21087);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2005-2917");

 name["english"] = "RHSA-2006-0045: squid";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated squid packages that fix a security vulnerability as well as
  several bugs are now available.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  Squid is a high-performance proxy caching server for Web clients,
  supporting FTP, gopher, and HTTP data objects.

  A denial of service flaw was found in the way squid processes certain NTLM
  authentication requests. A remote attacker could send a specially crafted
  NTLM authentication request which would cause the Squid server to crash.
  The Common Vulnerabilities and Exposures project assigned the name
  CVE-2005-2917 to this issue.

  Several bugs have also been addressed in this update:

  * An error introduced in 2.5.STABLE3-6.3E.14 where Squid can crash if a
  user visits a site which has a long DNS record.

  * Some authentication helpers were missing needed setuid rights.

  * Squid couldn\'t handle a reply from a HTTP server when the reply began
  with the new-line character or wasn\'t HTTP/1.0 or HTTP/1.1 compliant.

  * User-defined error pages were not kept when the squid package was
  upgraded.

  All users of squid should upgrade to these updated packages, which contain
  backported patches to resolve these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2006-0045.html
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
if ( rpm_check( reference:"squid-2.5.STABLE3-6.3E.16", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"squid-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2005-2917", value:TRUE);
}

set_kb_item(name:"RHSA-2006-0045", value:TRUE);
