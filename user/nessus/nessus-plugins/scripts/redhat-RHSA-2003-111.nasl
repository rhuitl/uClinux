#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12382);
 script_version ("$Revision: 1.7 $");
 script_cve_id("CVE-2002-1090", "CVE-2003-0140");

 name["english"] = "RHSA-2003-111: balsa";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated Balsa packages are available which fix potential vulnerabilities in
  the IMAP handling code and in libesmtp.

  Balsa is a GNOME email client which includes code from Mutt.

  A potential buffer overflow exists in Balsa versions 1.2 and higher when
  parsing mailbox names returned by an IMAP server. It is possible that a
  hostile IMAP server could cause arbitrary code to be executed by the user
  running Balsa.

  Additionally, a buffer overflow in libesmtp (an SMTP library used by Balsa)
  before version 0.8.11 allows a hostile remote SMTP server to execute
  arbitrary code via a certain response or cause a denial of service via long
  server responses.

  Users of Balsa are recommended to upgrade to these erratum packages which
  include updated versions of Balsa and libesmtp which are not vulnerable to
  these issues.

  Red Hat would like to thank CORE security for discovering the
  vulnerability, and the Mutt team for providing a patch.




Solution : http://rhn.redhat.com/errata/RHSA-2003-111.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the balsa packages";
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
if ( rpm_check( reference:"balsa-1.2.4-7.7.2", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libesmtp-0.8.12-0.7.x", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libesmtp-devel-0.8.12-0.7.x", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"balsa-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2002-1090", value:TRUE);
 set_kb_item(name:"CVE-2003-0140", value:TRUE);
}

set_kb_item(name:"RHSA-2003-111", value:TRUE);
