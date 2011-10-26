#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14624);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2004-0748");

 name["english"] = "RHSA-2004-349: httpd";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated httpd packages that include a security fix for mod_ssl and various
  enhancements are now available.

  The Apache HTTP server is a powerful, full-featured, efficient, and
  freely-available Web server.

  An input filter bug in mod_ssl was discovered in Apache httpd version
  2.0.50 and earlier. A remote attacker could force an SSL connection to be
  aborted in a particular state and cause an Apache child process to enter an
  infinite loop, consuming CPU resources. The Common Vulnerabilities and
  Exposures project (cve.mitre.org) has assigned the name CVE-2004-0748 to
  this issue.

  Additionally, this update includes the following enhancements and bug
  fixes:

  - included an improved version of the mod_cgi module that correctly handles
  concurrent output on stderr and stdout

  - included support for direct lookup of SSL variables using %{SSL:...}
  from mod_rewrite, or using %{...}s from mod_headers

  - restored support for use of SHA1-encoded passwords

  - added the mod_ext_filter module

  Users of the Apache HTTP server should upgrade to these updated packages,
  which contain backported patches that address these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2004-349.html
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
if ( rpm_check( reference:"httpd-2.0.46-38.ent", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"httpd-devel-2.0.46-38.ent", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mod_ssl-2.0.46-38.ent", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"httpd-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2004-0748", value:TRUE);
}

set_kb_item(name:"RHSA-2004-349", value:TRUE);
