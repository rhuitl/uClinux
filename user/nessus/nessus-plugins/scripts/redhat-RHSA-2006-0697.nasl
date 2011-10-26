#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(22473);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2006-4924", "CVE-2006-5051");

 name["english"] = "RHSA-2006-0697: openssh";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated openssh packages that fix two security flaws are now available for
  Red Hat Enterprise Linux 3 and 4.

  This update has been rated as having important security impact by the Red Hat
  Security Response Team.

  OpenSSH is OpenBSD\'s SSH (Secure SHell) protocol implementation. This
  package includes the core files necessary for both the OpenSSH client and
  server.

  Mark Dowd discovered a signal handler race condition in the OpenSSH sshd
  server. A remote attacker could possibly leverage this flaw to cause a
  denial of service (crash). (CVE-2006-5051) The OpenSSH project believes the
  likelihood of successful exploitation leading to arbitrary code execution
  appears remote. However, the Red Hat Security Response Team have not yet
  been able to verify this claim due to lack of upstream vulnerability
  information. We are therefore including a fix for this flaw and have rated
  it important security severity in the event our continued investigation
  finds this issue to be exploitable.

  Tavis Ormandy of the Google Security Team discovered a denial of service
  bug in the OpenSSH sshd server. A remote attacker can send a specially
  crafted SSH-1 request to the server causing sshd to consume a large
  quantity of CPU resources. (CVE-2006-4924)

  All users of openssh should upgrade to these updated packages, which
  contain backported patches that resolves these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2006-0697.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the openssh packages";
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
if ( rpm_check( reference:"openssh-3.6.1p2-33.30.12", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssh-askpass-3.6.1p2-33.30.12", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssh-askpass-gnome-3.6.1p2-33.30.12", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssh-clients-3.6.1p2-33.30.12", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssh-server-3.6.1p2-33.30.12", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssh-3.9p1-8.RHEL4.17", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssh-askpass-3.9p1-8.RHEL4.17", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssh-askpass-gnome-3.9p1-8.RHEL4.17", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssh-clients-3.9p1-8.RHEL4.17", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssh-server-3.9p1-8.RHEL4.17", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"openssh-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2006-4924", value:TRUE);
 set_kb_item(name:"CVE-2006-5051", value:TRUE);
}
if ( rpm_exists(rpm:"openssh-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2006-4924", value:TRUE);
 set_kb_item(name:"CVE-2006-5051", value:TRUE);
}

set_kb_item(name:"RHSA-2006-0697", value:TRUE);
