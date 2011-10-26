#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(17147);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2003-0297");

 name["english"] = "RHSA-2005-114: imap";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated imap packages that fix a security issue are now available for Red
  Hat Enterprise Linux 2.1.

  This update has been rated as having low security impact by the Red Hat
  Security Response Team.

  The imap package provides server daemons for both the IMAP (Internet
  Message Access Protocol) and POP (Post Office Protocol) mail access
  protocols.

  A buffer overflow flaw was found in the c-client IMAP client. An attacker
  could create a malicious IMAP server that if connected to by a victim could
  execute arbitrary code on the client machine. The Common Vulnerabilities
  and Exposures project (cve.mitre.org) has assigned the name CVE-2003-0297
  to this issue.

  Users of imap are advised to upgrade to these updated packages, which
  contain a backported patch to correct this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2005-114.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the imap packages";
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
if ( rpm_check( reference:"imap-2001a-11.0as", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"imap-devel-2001a-11.0as", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"imap-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2003-0297", value:TRUE);
}

set_kb_item(name:"RHSA-2005-114", value:TRUE);
