#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12473);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2004-0113");

 name["english"] = "RHSA-2004-084: httpd";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated httpd packages are now available that fix a denial of service
  vulnerability in mod_ssl and include various other bug fixes.

  The Apache HTTP server is a powerful, full-featured, efficient, and
  freely-available Web server.

  A memory leak in mod_ssl in the Apache HTTP Server prior to version 2.0.49
  allows a remote denial of service attack against an SSL-enabled server. The
  Common Vulnerabilities and Exposures project (cve.mitre.org) has assigned
  the name CVE-2004-0113 to this issue.

  This update also includes various bug fixes, including:

  - improvements to the mod_expires, mod_dav, mod_ssl and mod_proxy modules

  - a fix for a bug causing core dumps during configuration parsing on the
  IA64 platform

  - an updated version of mod_include fixing several edge cases in the SSI
  parser

  Additionally, the mod_logio module is now included.

  Users of the Apache HTTP server should upgrade to these updated packages,
  which contain backported patches that address these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2004-084.html
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
if ( rpm_check( reference:"httpd-2.0.46-32.ent", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"httpd-devel-2.0.46-32.ent", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mod_ssl-2.0.46-32.ent", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"httpd-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2004-0113", value:TRUE);
}

set_kb_item(name:"RHSA-2004-084", value:TRUE);
