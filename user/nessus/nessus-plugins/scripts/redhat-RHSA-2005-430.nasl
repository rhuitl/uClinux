#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18407);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-1431");

 name["english"] = "RHSA-2005-430: gnutls";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated GnuTLS packages that fix a remote denial of service
  vulnerability are available for Red Hat Enterprise Linux 4.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  The GnuTLS library implements Secure Sockets Layer (SSL v3) and Transport
  Layer Security (TLS v1) protocols.

  A denial of service bug was found in the GnuTLS library versions prior to
  1.0.25. A remote attacker could perform a carefully crafted TLS handshake
  against a service that uses the GnuTLS library causing the service to
  crash. The Common Vulnerabilities and Exposures project (cve.mitre.org) has
  assigned the name CVE-2005-1431 to this issue.

  All users of GnuTLS are advised to upgrade to these updated packages and to
  restart any services which use GnuTLS.




Solution : http://rhn.redhat.com/errata/RHSA-2005-430.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the gnutls packages";
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
if ( rpm_check( reference:"gnutls-1.0.20-3.2.1", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gnutls-devel-1.0.20-3.2.1", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"gnutls-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2005-1431", value:TRUE);
}

set_kb_item(name:"RHSA-2005-430", value:TRUE);
