#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19830);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2004-2069");

 name["english"] = "RHSA-2005-550: openssh";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated openssh packages that fix a potential security vulnerability and
  various other bugs are now available.

  This update has been rated as having low security impact by the Red Hat
  Security Response Team.

  OpenSSH is OpenBSD\'s SSH (Secure SHell) protocol implementation. This
  includes the core files necessary for both the OpenSSH client and server.

  A bug was found in the way the OpenSSH server handled the MaxStartups and
  LoginGraceTime configuration variables. A malicious user could connect to
  the SSH daemon in such a way that it would prevent additional logins from
  occuring until the malicious connections are closed. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CVE-2004-2069 to this issue.

  Additionally, the following issues are resolved with this update:

  - The -q option of the ssh client did not suppress the banner message sent
  by the server, which caused errors when used in scripts.

  - The sshd daemon failed to close the client connection if multiple X
  clients were forwarded over the connection and the client session exited.

  - The sftp client leaked memory if used for extended periods.

  - The sshd daemon called the PAM functions incorrectly if the user was
  unknown on the system.

  All users of openssh should upgrade to these updated packages, which
  contain backported patches and resolve these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2005-550.html
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
if ( rpm_check( reference:"openssh-3.6.1p2-33.30.6", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssh-askpass-3.6.1p2-33.30.6", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssh-askpass-gnome-3.6.1p2-33.30.6", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssh-clients-3.6.1p2-33.30.6", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssh-server-3.6.1p2-33.30.6", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"openssh-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2004-2069", value:TRUE);
}

set_kb_item(name:"RHSA-2005-550", value:TRUE);
