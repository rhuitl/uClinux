#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18423);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2004-0175");

 name["english"] = "RHSA-2005-481: openssh";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated openssh packages that fix a potential security vulnerability and
  various other bugs are now available for Red Hat Enterprise Linux 2.1.

  This update has been rated as having low security impact by the Red Hat
  Security Response Team.

  OpenSSH is OpenBSD\'s SSH (Secure SHell) protocol implementation. SSH
  replaces rlogin and rsh, and provides secure encrypted communications
  between two untrusted hosts over an insecure network. X11 connections and
  arbitrary TCP/IP ports can also be forwarded over a secure channel. Public
  key authentication can be used for "passwordless" access to servers.

  The scp protocol allows a server to instruct a client to write to arbitrary
  files outside of the current directory. This could potentially cause a
  security issue if a user uses scp to copy files from a malicious server.
  The Common Vulnerabilities and Exposures project (cve.mitre.org) has
  assigned the name CVE-2004-0175 to this issue.

  These updated packages also correct the following bug:

  On systems in which direct ssh access for the root user was disabled by
  configuration (setting "PermitRootLogin no"), attempts to guess the root
  password could be judged as sucessful or unsucessful by observing a delay.

  Users of openssh should upgrade to these updated packages, which contain
  backported patches to resolve these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2005-481.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the openssh packages";
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
if ( rpm_check( reference:"openssh-3.1p1-18", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssh-askpass-3.1p1-18", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssh-askpass-gnome-3.1p1-18", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssh-clients-3.1p1-18", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssh-server-3.1p1-18", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"openssh-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2004-0175", value:TRUE);
}

set_kb_item(name:"RHSA-2005-481", value:TRUE);
