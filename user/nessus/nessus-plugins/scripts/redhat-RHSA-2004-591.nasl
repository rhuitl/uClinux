#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(15533);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2004-0918");

 name["english"] = "RHSA-2004-591: squid";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  An updated squid package that fixes a remote denial of service
  vulnerability
  is now avaliable.

  Squid is a full-featured Web proxy cache.

  iDEFENSE reported a flaw in the squid SNMP module. This flaw could allow
  an attacker who has the ability to send arbitrary packets to the SNMP port
  to restart the server, causing it to drop all open connections. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CVE-2004-0918 to this issue.

  All users of squid should update to this erratum package, which contains a
  backport of the security fix for this vulnerability.




Solution : http://rhn.redhat.com/errata/RHSA-2004-591.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the squid packages";
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
if ( rpm_check( reference:"squid-2.4.STABLE7-1.21as", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"squid-2.5.STABLE3-6.3E.2", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"squid-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2004-0918", value:TRUE);
}
if ( rpm_exists(rpm:"squid-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2004-0918", value:TRUE);
}

set_kb_item(name:"RHSA-2004-591", value:TRUE);
