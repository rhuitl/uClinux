#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(22330);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2006-2941", "CVE-2006-3636");

 name["english"] = "RHSA-2006-0600: mailman";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated mailman packages that fix security issues are now available for Red
  Hat Enterprise Linux 3 and 4.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  Mailman is a program used to help manage email discussion lists.

  A flaw was found in the way Mailman handled MIME multipart messages. An
  attacker could send a carefully crafted MIME multipart email message to a
  mailing list run by Mailman which caused that particular mailing list
  to stop working. (CVE-2006-2941)

  Several cross-site scripting (XSS) issues were found in Mailman. An
  attacker could exploit these issues to perform cross-site scripting attacks
  against the Mailman administrator. (CVE-2006-3636)

  Red Hat would like to thank Barry Warsaw for disclosing these
  vulnerabilities.

  Users of Mailman should upgrade to these updated packages, which contain
  backported patches to correct this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2006-0600.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the mailman packages";
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
if ( rpm_check( reference:"mailman-2.1.5.1-25.rhel3.7", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mailman-2.1.5.1-34.rhel4.5", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"mailman-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2006-2941", value:TRUE);
 set_kb_item(name:"CVE-2006-3636", value:TRUE);
}
if ( rpm_exists(rpm:"mailman-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2006-2941", value:TRUE);
 set_kb_item(name:"CVE-2006-3636", value:TRUE);
}

set_kb_item(name:"RHSA-2006-0600", value:TRUE);
