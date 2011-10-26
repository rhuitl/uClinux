#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12309);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2002-t-0011");
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2002-0640");

 name["english"] = "RHSA-2002-131: openssh";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated openssh packages are now available for Red Hat Linux Advanced
  Server. These updates fix an input validation error in OpenSSH.

  OpenSSH provides an implementation of the SSH (secure shell) protocol used
  for logging into and executing commands on remote machines.

  Versions of the OpenSSH server between 2.3.1 and 3.3 contain an input
  validation error that can result in an integer overflow and privilege
  escalation.

  At this time, Red Hat does not believe that the default installation of
  OpenSSH on Red Hat Linux is vulnerable to this issue; however a user would
  be vulnerable if the configuration option "PAMAuthenticationViaKbdInt" is
  enabled in the sshd configuration file (it is not enabled by default).

  We have applied the security fix provided by the OpenSSH team to these
  errata packages which are based on OpenSSH 3.1p1. This should minimize the
  impact of upgrading to our errata packages.

  All users of OpenSSH should update to these errata packages which are not
  vulnerable to this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2002-131.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the openssh packages";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Red Hat Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"openssh-3.1p1-6", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssh-askpass-3.1p1-6", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssh-askpass-gnome-3.1p1-6", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssh-clients-3.1p1-6", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssh-server-3.1p1-6", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"openssh-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2002-0640", value:TRUE);
}

set_kb_item(name:"RHSA-2002-131", value:TRUE);
