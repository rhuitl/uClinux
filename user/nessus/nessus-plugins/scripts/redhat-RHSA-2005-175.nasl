#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(17265);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-0205");

 name["english"] = "RHSA-2005-175: kdenetwork";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated kdenetwork packages that fix a file descriptor leak are now
  available.

  This update has been rated as having low security impact by the Red Hat
  Security Response Team

  The kdenetwork packages contain a collection of networking applications for
  the K Desktop Environment.

  A bug was found in the way kppp handles privileged file descriptors. A
  malicious local user could make use of this flaw to modify the /etc/hosts
  or /etc/resolv.conf files, which could be used to spoof domain information.
  The Common Vulnerabilities and Exposures project (cve.mitre.org) has
  assigned the name CVE-2005-0205 to this issue.

  Please note that the default installation of kppp on Red Hat Enterprise
  Linux uses consolehelper and is not vulnerable to this issue. However, the
  kppp FAQ provides instructions for removing consolehelper and running kppp
  suid root, which is a vulnerable configuration.

  Users of kdenetwork should upgrade to these updated packages, which contain
  a backported patch, and are not vulnerable to this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2005-175.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the kdenetwork packages";
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
if ( rpm_check( reference:"kdenetwork-2.2.2-3.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdenetwork-ppp-2.2.2-3.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdenetwork-3.1.3-1.8", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdenetwork-devel-3.1.3-1.8", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"kdenetwork-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2005-0205", value:TRUE);
}
if ( rpm_exists(rpm:"kdenetwork-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2005-0205", value:TRUE);
}

set_kb_item(name:"RHSA-2005-175", value:TRUE);
