#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16148);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2003-0297");

 name["english"] = "RHSA-2005-015: pine";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  An updated Pine package is now available for Red Hat Enterprise Linux 2.1
  to fix a denial of service attack.

  Pine is an email user agent.

  The c-client IMAP client library, as used in Pine 4.44 contains an integer
  overflow and integer signedness flaw. An attacker could create a malicious
  IMAP server in such a way that it would cause Pine to crash. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CVE-2003-0297 to this issue.

  Users of Pine are advised to upgrade to these erratum packages which
  contain a backported patch to correct this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2005-015.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the pine packages";
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
if ( rpm_check( reference:"pine-4.44-20", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"pine-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2003-0297", value:TRUE);
}

set_kb_item(name:"RHSA-2005-015", value:TRUE);
