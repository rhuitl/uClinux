#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12441);
 script_version ("$Revision: 1.6 $");
 script_cve_id("CVE-2003-0963");

 name["english"] = "RHSA-2003-404: lftp";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated lftp packages are now available that fix a buffer overflow
  security vulnerability.

  lftp is a command-line file transfer program supporting FTP and HTTP
  protocols.

  Ulf Härnhammar discovered a buffer overflow bug in versions of lftp up to
  and including 2.6.9. An attacker could create a carefully crafted
  directory on a website such that, if a user connects to that directory
  using the lftp client and subsequently issues a \'ls\' or \'rels\' command, the
  attacker could execute arbitrary code on the users machine. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CVE-2003-0963 to this issue.

  Users of lftp are advised to upgrade to these erratum packages, which
  contain a backported security patch and are not vulnerable to this issue.

  Red Hat would like to thank Ulf Härnhammar for discovering and alerting us
  to this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2003-404.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the lftp packages";
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
if ( rpm_check( reference:"lftp-2.4.9-2", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"lftp-2.6.3-5", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"lftp-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2003-0963", value:TRUE);
}
if ( rpm_exists(rpm:"lftp-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2003-0963", value:TRUE);
}

set_kb_item(name:"RHSA-2003-404", value:TRUE);
