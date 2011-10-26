#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(22045);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2006-3242");

 name["english"] = "RHSA-2006-0577: mutt";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated mutt packages that fix a security issue are now available.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  Mutt is a text-mode mail user agent.

  A buffer overflow flaw was found in the way Mutt processes an overly
  long namespace from a malicious imap server. In order to exploit this
  flaw a user would have to use Mutt to connect to a malicious IMAP server.
  (CVE-2006-3242)

  Users of Mutt are advised to upgrade to these erratum packages, which
  contain a backported patch to correct this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2006-0577.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the mutt packages";
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
if ( rpm_check( reference:"mutt-1.2.5.1-2.rhel21", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mutt-1.4.1-3.5.rhel3", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mutt-1.4.1-11.rhel4", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"mutt-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2006-3242", value:TRUE);
}
if ( rpm_exists(rpm:"mutt-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2006-3242", value:TRUE);
}
if ( rpm_exists(rpm:"mutt-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2006-3242", value:TRUE);
}

set_kb_item(name:"RHSA-2006-0577", value:TRUE);
