#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(17645);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-0468", "CVE-2005-0469");

 name["english"] = "RHSA-2005-327: telnet";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated telnet packages that fix two buffer overflow vulnerabilities are
  now available.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  The telnet package provides a command line telnet client. The telnet-server
  package includes a telnet daemon, telnetd, that supports remote login to
  the host machine.

  Two buffer overflow flaws were discovered in the way the telnet client
  handles messages from a server. An attacker may be able to execute
  arbitrary code on a victim\'s machine if the victim can be tricked into
  connecting to a malicious telnet server. The Common Vulnerabilities and
  Exposures project (cve.mitre.org) has assigned the names CVE-2005-0468
  and CVE-2005-0469 to these issues.

  Additionally, the following bugs have been fixed in these erratum packages
  for Red Hat Enterprise Linux 2.1 and Red Hat Enterprise Linux 3:

  - telnetd could loop on an error in the child side process

  - There was a race condition in telnetd on a wtmp lock on some occasions

  - The command line in the process table was sometimes too long and caused
  bad output from the ps command

  - The 8-bit binary option was not working

  Users of telnet should upgrade to this updated package, which contains
  backported patches to correct these issues.

  Red Hat would like to thank iDEFENSE for their responsible disclosure of
  this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2005-327.html
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
if ( rpm_check( reference:"telnet-0.17-20.EL2.3", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"telnet-server-0.17-20.EL2.3", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"telnet-0.17-26.EL3.2", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"telnet-server-0.17-26.EL3.2", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"telnet-0.17-31.EL4.2", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"telnet-server-0.17-31.EL4.2", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"telnet-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2005-0468", value:TRUE);
 set_kb_item(name:"CVE-2005-0469", value:TRUE);
}
if ( rpm_exists(rpm:"telnet-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2005-0468", value:TRUE);
 set_kb_item(name:"CVE-2005-0469", value:TRUE);
}
if ( rpm_exists(rpm:"telnet-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2005-0468", value:TRUE);
 set_kb_item(name:"CVE-2005-0469", value:TRUE);
}

set_kb_item(name:"RHSA-2005-327", value:TRUE);
