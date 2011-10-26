#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16371);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-0202");

 name["english"] = "RHSA-2005-136: mailman";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated mailman packages that correct a mailman security issue are now
  available.

  The mailman package is software to help manage email discussion lists.

  A flaw in the true_path function of Mailman was discovered. A remote
  attacker who is a member of a private mailman list could use a carefully
  crafted URL and gain access to arbitrary files on the server. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CVE-2005-0202 to this issue.

  Note: Mailman installations running on Apache 2.0-based servers are not
  vulnerable to this issue.

  Users of mailman should update to these erratum packages that contain a
  patch and are not vulnerable to this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2005-136.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the mailman packages";
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
if ( rpm_check( reference:"mailman-2.0.13-7", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mailman-2.1.5-24.rhel3", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"mailman-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2005-0202", value:TRUE);
}
if ( rpm_exists(rpm:"mailman-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2005-0202", value:TRUE);
}

set_kb_item(name:"RHSA-2005-136", value:TRUE);
