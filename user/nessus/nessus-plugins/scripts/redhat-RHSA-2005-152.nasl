#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(17339);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-0337");

 name["english"] = "RHSA-2005-152: postfix";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated postfix packages that include a security fix and two other bug
  fixes are now available for Red Hat Enterprise Linux 4.

  This update has been rated as having low security impact by the Red Hat
  Security Response Team

  Postfix is a Mail Transport Agent (MTA), supporting LDAP, SMTP AUTH (SASL),
  and TLS.

  A flaw was found in the ipv6 patch used with Postfix. When the file
  /proc/net/if_inet6 is not available and permit_mx_backup is enabled in
  smtpd_recipient_restrictions, this flaw could allow remote attackers to
  bypass e-mail restrictions and perform mail relaying by sending mail to an
  IPv6 hostname. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CVE-2005-0337 to this issue.

  These updated packages also fix the following problems:

  - wrong permissions on doc directory
  - segfault when gethostbyname or gethostbyaddr fails

  All users of postfix should upgrade to these updated packages, which
  contain patches which resolve these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2005-152.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the postfix packages";
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
if ( rpm_check( reference:"postfix-2.1.5-4.2.RHEL4", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"postfix-pflogsumm-2.1.5-4.2.RHEL4", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"postfix-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2005-0337", value:TRUE);
}

set_kb_item(name:"RHSA-2005-152", value:TRUE);
