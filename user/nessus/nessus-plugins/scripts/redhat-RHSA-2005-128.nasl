#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(17207);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-0198");

 name["english"] = "RHSA-2005-128: imap";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated imap packages to correct a security vulnerability in CRAM-MD5
  authentication are now available for Red Hat Enterprise Linux 3.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  The imap package provides server daemons for both the IMAP (Internet
  Message Access Protocol) and POP (Post Office Protocol) mail access
  protocols.

  A logic error in the CRAM-MD5 code in the University of Washington IMAP
  (UW-IMAP) server was discovered. When Challenge-Response Authentication
  Mechanism with MD5 (CRAM-MD5) is enabled, UW-IMAP does not properly enforce
  all the required conditions for successful authentication, which could
  allow remote attackers to authenticate as arbitrary users. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CVE-2005-0198 to this issue.

  All users of imap should upgrade to these updated packages, which contain a
  backported patch and are not vulnerable to this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2005-128.html
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
if ( rpm_check( reference:"imap-2002d-11", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"imap-devel-2002d-11", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"imap-utils-2002d-11", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"imap-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2005-0198", value:TRUE);
}

set_kb_item(name:"RHSA-2005-128", value:TRUE);
