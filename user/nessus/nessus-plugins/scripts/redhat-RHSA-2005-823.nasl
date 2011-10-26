#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20106);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2005-3088");

 name["english"] = "RHSA-2005-823: fetchmail";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated fetchmail packages that fix insecure configuration file creation is
  now available.

  This update has been rated as having low security impact by the Red Hat
  Security Response Team.

  Fetchmail is a remote mail retrieval and forwarding utility.

  A bug was found in the way the fetchmailconf utility program writes
  configuration files. The default behavior of fetchmailconf is to write a
  configuration file which may be world readable for a short period of time.
  This configuration file could provide passwords to a local malicious
  attacker within the short window before fetchmailconf sets secure
  permissions. The Common Vulnerabilities and Exposures project has assigned
  the name CVE-2005-3088 to this issue.

  Users of fetchmail are advised to upgrade to these updated packages, which
  contain a backported patch which resolves this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2005-823.html
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
if ( rpm_check( reference:"fetchmail-5.9.0-21.7.3.el2.1.2", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"fetchmailconf-5.9.0-21.7.3.el2.1.2", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"fetchmail-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2005-3088", value:TRUE);
}

set_kb_item(name:"RHSA-2005-823", value:TRUE);
