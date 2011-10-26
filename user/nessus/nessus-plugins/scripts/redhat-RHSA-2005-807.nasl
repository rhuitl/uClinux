#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20143);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2005-3185");

 name["english"] = "RHSA-2005-807: curl";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated curl packages that fix a security issue are now available.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  cURL is a tool for getting files from FTP, HTTP, Gopher, Telnet, and Dict
  servers, using any of the supported protocols.

  A stack based buffer overflow bug was found in cURL\'s NTLM authentication
  module. It is possible to execute arbitrary code on a user\'s machine if
  the user can be tricked into connecting to a malicious web server using
  NTLM authentication. The Common Vulnerabilities and Exposures project
  has assigned the name CVE-2005-3185 to this issue.

  All users of curl are advised to upgrade to these updated packages, which
  contain a backported patch that resolve this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2005-807.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the curl packages";
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
if ( rpm_check( reference:"curl-7.10.6-7.rhel3", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"curl-devel-7.10.6-7.rhel3", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"curl-7.12.1-6.rhel4", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"curl-devel-7.12.1-6.rhel4", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"curl-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2005-3185", value:TRUE);
}
if ( rpm_exists(rpm:"curl-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2005-3185", value:TRUE);
}

set_kb_item(name:"RHSA-2005-807", value:TRUE);
