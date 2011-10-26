#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20144);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2005-3185");

 name["english"] = "RHSA-2005-812: wget";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated wget packages that fix a security issue are now available.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  GNU Wget is a file retrieval utility that can use either the HTTP or
  FTP protocols.

  A stack based buffer overflow bug was found in the wget implementation of
  NTLM authentication. An attacker could execute arbitrary code on a user\'s
  machine if the user can be tricked into connecting to a malicious web
  server using NTLM authentication. The Common Vulnerabilities and Exposures
  project has assigned the name CVE-2005-3185 to this issue.

  All users of wget are advised to upgrade to these updated packages, which
  contain a backported patch that resolves this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2005-812.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the wget packages";
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
if ( rpm_check( reference:"wget-1.10.2-0.AS21", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"wget-1.10.2-0.30E", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"wget-1.10.2-0.40E", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"wget-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2005-3185", value:TRUE);
}
if ( rpm_exists(rpm:"wget-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2005-3185", value:TRUE);
}
if ( rpm_exists(rpm:"wget-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2005-3185", value:TRUE);
}

set_kb_item(name:"RHSA-2005-812", value:TRUE);
