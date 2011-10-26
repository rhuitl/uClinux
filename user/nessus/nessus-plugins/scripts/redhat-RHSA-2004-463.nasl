#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14736);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2004-0747", "CVE-2004-0751", "CVE-2004-0786", "CVE-2004-0809");

 name["english"] = "RHSA-2004-463: httpd";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated httpd packages that include fixes for security issues are now
  available.

  The Apache HTTP server is a powerful, full-featured, efficient, and
  freely-available Web server.

  Four issues have been discovered affecting releases of the Apache HTTP 2.0
  Server, up to and including version 2.0.50:

  Testing using the Codenomicon HTTP Test Tool performed by the Apache
  Software Foundation security group and Red Hat uncovered an input
  validation issue in the IPv6 URI parsing routines in the apr-util library.
  If a remote attacker sent a request including a carefully crafted URI, an
  httpd child process could be made to crash. This issue is not believed to
  allow arbitrary code execution on Red Hat Enterprise Linux. This issue
  also does not represent a significant denial of service attack as requests
  will continue to be handled by other Apache child processes. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CVE-2004-0786 to this issue.

  The Swedish IT Incident Centre (SITIC) reported a buffer overflow in the
  expansion of environment variables during configuration file parsing. This
  issue could allow a local user to gain \'apache\' privileges if an httpd
  process can be forced to parse a carefully crafted .htaccess file written
  by a local user. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CVE-2004-0747 to this issue.

  An issue was discovered in the mod_ssl module which could be triggered if
  the server is configured to allow proxying to a remote SSL server. A
  malicious remote SSL server could force an httpd child process to crash by
  sending a carefully crafted response header. This issue is not believed to
  allow execution of arbitrary code. This issue also does not represent a
  significant Denial of Service attack as requests will continue to be
  handled by other Apache child processes. The Common Vulnerabilities and
  Exposures project (cve.mitre.org) has assigned the name CVE-2004-0751 to
  this issue.

  An issue was discovered in the mod_dav module which could be triggered for
  a location where WebDAV authoring access has been configured. A malicious
  remote client which is authorized to use the LOCK method could force an
  httpd child process to crash by sending a particular sequence of LOCK
  requests. This issue does not allow execution of arbitrary code. This
  issue also does not represent a significant Denial of Service attack as
  requests will continue to be handled by other Apache child processes. The
  Common Vulnerabilities and Exposures project (cve.mitre.org) has assigned
  the name CVE-2004-0809 to this issue.

  Users of the Apache HTTP server should upgrade to these updated packages,
  which contain backported patches that address these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2004-463.html
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
if ( rpm_check( reference:"httpd-2.0.46-40.ent", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"httpd-devel-2.0.46-40.ent", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mod_ssl-2.0.46-40.ent", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"httpd-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2004-0747", value:TRUE);
 set_kb_item(name:"CVE-2004-0751", value:TRUE);
 set_kb_item(name:"CVE-2004-0786", value:TRUE);
 set_kb_item(name:"CVE-2004-0809", value:TRUE);
}

set_kb_item(name:"RHSA-2004-463", value:TRUE);
