#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(15700);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2004-0885", "CVE-2004-0942");

 name["english"] = "RHSA-2004-562: httpd";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated httpd packages that include fixes for two security issues, as well
  as
  other bugs, are now available.

  The Apache HTTP server is a powerful, full-featured, efficient, and
  freely-available Web server.

  An issue has been discovered in the mod_ssl module when configured to use
  the "SSLCipherSuite" directive in directory or location context. If a
  particular location context has been configured to require a specific set
  of cipher suites, then a client will be able to access that location using
  any cipher suite allowed by the virtual host configuration. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CVE-2004-0885 to this issue.

  An issue has been discovered in the handling of white space in request
  header lines using MIME folding. A malicious client could send a carefully
  crafted request, forcing the server to consume large amounts of memory,
  leading to a denial of service. The Common Vulnerabilities and Exposures
  project (cve.mitre.org) has assigned the name CVE-2004-0942 to this issue.

  Several minor bugs were also discovered, including:

  - In the mod_cgi module, problems that arise when CGI scripts are
  invoked from SSI pages by mod_include using the "#include virtual"
  syntax have been fixed.

  - In the mod_dav_fs module, problems with the handling of indirect locks
  on the S/390x platform have been fixed.

  Users of the Apache HTTP server who are affected by these issues should
  upgrade to these updated packages, which contain backported patches.




Solution : http://rhn.redhat.com/errata/RHSA-2004-562.html
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
if ( rpm_check( reference:"httpd-2.0.46-44.ent", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"httpd-devel-2.0.46-44.ent", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mod_ssl-2.0.46-44.ent", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"httpd-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2004-0885", value:TRUE);
 set_kb_item(name:"CVE-2004-0942", value:TRUE);
}

set_kb_item(name:"RHSA-2004-562", value:TRUE);
