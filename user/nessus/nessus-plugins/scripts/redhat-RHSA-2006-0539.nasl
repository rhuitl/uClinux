#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(22043);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2006-2607");

 name["english"] = "RHSA-2006-0539: vixie";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated vixie-cron packages that fix a privilege escalation issue are now
  available.

  This update has been rated as having important security impact by the Red
  Hat
  Security Response Team.

  The vixie-cron package contains the Vixie version of cron. Cron is a
  standard UNIX daemon that runs specified programs at scheduled times.

  A privilege escalation flaw was found in the way Vixie Cron runs programs;
  vixie-cron does not properly verify an attempt to set the current process
  user id succeeded. It was possible for a malicious local users who
  exhausted certain limits to execute arbitrary commands as root via cron.
  (CVE-2006-2607)

  All users of vixie-cron should upgrade to these updated packages, which
  contain a backported patch to correct this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2006-0539.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the vixie packages";
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
if ( rpm_check( reference:"vixie-cron-4.1-44.EL4", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"vixie-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2006-2607", value:TRUE);
}

set_kb_item(name:"RHSA-2006-0539", value:TRUE);
