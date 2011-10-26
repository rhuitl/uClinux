#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20269);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2005-2933");

 name["english"] = "RHSA-2005-848: libc";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated libc-client packages that fix a buffer overflow issue are now
  available.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  C-client is a common API for accessing mailboxes.

  A buffer overflow flaw was discovered in the way C-client parses user
  supplied mailboxes. If an authenticated user requests a specially crafted
  mailbox name, it may be possible to execute arbitrary code on a server that
  uses C-client to access mailboxes. The Common Vulnerabilities and Exposures
  project has assigned the name CVE-2005-2933 to this issue.

  All users of libc-client should upgrade to these updated packages, which
  contain a backported patch that resolves this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2005-848.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the libc packages";
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
if ( rpm_check( reference:"libc-client-2002e-14", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libc-client-devel-2002e-14", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"libc-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2005-2933", value:TRUE);
}

set_kb_item(name:"RHSA-2005-848", value:TRUE);
