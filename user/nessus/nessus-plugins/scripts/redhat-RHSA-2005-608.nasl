#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19673);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-2700", "CVE-2005-2728");

 name["english"] = "RHSA-2005-608: httpd";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated Apache httpd packages that correct two security issues are now
  available for Red Hat Enterprise Linux 3 and 4.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  The Apache HTTP Server is a popular and freely-available Web server.

  A flaw was discovered in mod_ssl\'s handling of the "SSLVerifyClient"
  directive. This flaw occurs if a virtual host is configured
  using "SSLVerifyClient optional" and a directive "SSLVerifyClient
  required" is set for a specific location. For servers configured in this
  fashion, an attacker may be able to access resources that should otherwise
  be protected, by not supplying a client certificate when connecting. The
  Common Vulnerabilities and Exposures project assigned the name
  CVE-2005-2700 to this issue.

  A flaw was discovered in Apache httpd where the byterange filter would
  buffer certain responses into memory. If a server has a dynamic
  resource such as a CGI script or PHP script that generates a large amount
  of data, an attacker could send carefully crafted requests in order to
  consume resources, potentially leading to a Denial of Service.
  (CVE-2005-2728)

  Users of Apache httpd should update to these errata packages that contain
  backported patches to correct these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2005-608.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the httpd packages";
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
if ( rpm_check( reference:"httpd-2.0.46-46.3.ent", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"httpd-devel-2.0.46-46.3.ent", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mod_ssl-2.0.46-46.3.ent", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"httpd-2.0.52-12.2.ent", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"httpd-devel-2.0.52-12.2.ent", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"httpd-manual-2.0.52-12.2.ent", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"httpd-suexec-2.0.52-12.2.ent", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mod_ssl-2.0.52-12.2.ent", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"httpd-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2005-2700", value:TRUE);
 set_kb_item(name:"CVE-2005-2728", value:TRUE);
}
if ( rpm_exists(rpm:"httpd-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2005-2700", value:TRUE);
 set_kb_item(name:"CVE-2005-2728", value:TRUE);
}

set_kb_item(name:"RHSA-2005-608", value:TRUE);
