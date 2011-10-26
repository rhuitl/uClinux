#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20270);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2005-2933");

 name["english"] = "RHSA-2005-850: imap";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  An updated imap package that fixes a buffer overflow issue is now
  available.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  The imap package provides server daemons for both the IMAP (Internet
  Message Access Protocol) and POP (Post Office Protocol) mail access
  protocols.

  A buffer overflow flaw was discovered in the way the c-client library
  parses user supplied mailboxes. If an authenticated user requests a
  specially crafted mailbox name, it may be possible to execute arbitrary
  code on a server that uses the library. The Common Vulnerabilities and
  Exposures project has assigned the name CVE-2005-2933 to this issue.

  All users of imap should upgrade to these updated packages, which contain a
  backported patch and are not vulnerable to this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2005-850.html
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
if ( rpm_check( reference:"imap-2001a-19", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"imap-devel-2001a-19", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"imap-2002d-12", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"imap-devel-2002d-12", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"imap-utils-2002d-12", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"imap-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2005-2933", value:TRUE);
}
if ( rpm_exists(rpm:"imap-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2005-2933", value:TRUE);
}

set_kb_item(name:"RHSA-2005-850", value:TRUE);
