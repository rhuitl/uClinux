#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19297);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-2335");

 name["english"] = "RHSA-2005-640: fetchmail";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated fetchmail packages that fix a security flaw are now available.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  Fetchmail is a remote mail retrieval and forwarding utility.

  A buffer overflow was discovered in fetchmail\'s POP3 client. A malicious
  server could cause send a carefully crafted message UID and cause fetchmail
  to crash or potentially execute arbitrary code as the user running
  fetchmail. The Common Vulnerabilities and Exposures project assigned the
  name CVE-2005-2335 to this issue.

  Users of fetchmail should update to this erratum package which contains a
  backported patch to correct this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2005-640.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the fetchmail packages";
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
if ( rpm_check( reference:"fetchmail-5.9.0-21.7.3.el2.1.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"fetchmailconf-5.9.0-21.7.3.el2.1.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"fetchmail-6.2.0-3.el3.2", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"fetchmail-6.2.5-6.el4.2", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"fetchmail-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2005-2335", value:TRUE);
}
if ( rpm_exists(rpm:"fetchmail-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2005-2335", value:TRUE);
}
if ( rpm_exists(rpm:"fetchmail-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2005-2335", value:TRUE);
}

set_kb_item(name:"RHSA-2005-640", value:TRUE);
