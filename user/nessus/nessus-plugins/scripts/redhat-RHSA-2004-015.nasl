#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12450);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2003-0542");

 name["english"] = "RHSA-2004-015: httpd";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated httpd packages that fix two minor security issues in the Apache Web
  server are now available for Red Hat Enterprise Linux 3.

  The Apache HTTP Server is a powerful, full-featured, efficient, and
  freely-available Web server.

  An issue in the handling of regular expressions from configuration files
  was discovered in releases of the Apache HTTP Server version 2.0 prior to
  2.0.48. To exploit this issue an attacker would need to have the ability
  to write to Apache configuration files such as .htaccess or httpd.conf. A
  carefully-crafted configuration file can cause an exploitable buffer
  overflow and would allow the attacker to execute arbitrary code in the
  context of the server (in default configurations as the \'apache\' user).
  The Common Vulnerabilities and Exposures project (cve.mitre.org) has
  assigned the name CVE-2003-0542 to this issue.

  Users of the Apache HTTP Server should upgrade to these erratum packages,
  which contain backported patches correcting these issues, and are applied
  to Apache version 2.0.46. This update also includes fixes for a number of
  minor bugs found in this version of the Apache HTTP Server.




Solution : http://rhn.redhat.com/errata/RHSA-2004-015.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the httpd packages";
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
if ( rpm_check( reference:"httpd-2.0.46-26.ent", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"httpd-devel-2.0.46-26.ent", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mod_ssl-2.0.46-26.ent", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"httpd-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2003-0542", value:TRUE);
}

set_kb_item(name:"RHSA-2004-015", value:TRUE);
