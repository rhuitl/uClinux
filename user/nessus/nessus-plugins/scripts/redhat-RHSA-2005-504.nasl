#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18501);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-0488");

 name["english"] = "RHSA-2005-504: telnet";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated telnet packages that fix an information disclosure issue are now
  available.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  The telnet package provides a command line telnet client.

  Gael Delalleau discovered an information disclosure issue in the way the
  telnet client handles messages from a server. An attacker could construct
  a malicious telnet server that collects information from the environment of
  any victim who connects to it. The Common Vulnerabilities and Exposures
  project (cve.mitre.org) has assigned the name CVE-2005-0488 to this issue.

  Users of telnet should upgrade to this updated package, which contains a
  backported patch to correct this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2005-504.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the telnet packages";
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
if ( rpm_check( reference:"telnet-0.17-20.EL2.4", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"telnet-server-0.17-20.EL2.4", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"telnet-0.17-26.EL3.3", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"telnet-server-0.17-26.EL3.3", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"telnet-0.17-31.EL4.3", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"telnet-server-0.17-31.EL4.3", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"telnet-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2005-0488", value:TRUE);
}
if ( rpm_exists(rpm:"telnet-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2005-0488", value:TRUE);
}
if ( rpm_exists(rpm:"telnet-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2005-0488", value:TRUE);
}

set_kb_item(name:"RHSA-2005-504", value:TRUE);
