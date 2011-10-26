#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19296);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-1268", "CVE-2005-2088");
 script_bugtraq_id(14366);

 name["english"] = "RHSA-2005-582: httpd";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated Apache httpd packages to correct two security issues are now
  available for Red Hat Enterprise Linux 3 and 4.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  The Apache HTTP Server is a powerful, full-featured, efficient, and
  freely-available Web server.

  Watchfire reported a flaw that occured when using the Apache server as an
  HTTP proxy. A remote attacker could send an HTTP request with both a
  "Transfer-Encoding: chunked" header and a "Content-Length" header. This
  caused Apache to incorrectly handle and forward the body of the request in
  a way that the receiving server processes it as a separate HTTP request.
  This could allow the bypass of Web application firewall protection or lead
  to cross-site scripting (XSS) attacks. The Common Vulnerabilities and
  Exposures project (cve.mitre.org) assigned the name CVE-2005-2088 to this
  issue.

  Marc Stern reported an off-by-one overflow in the mod_ssl CRL verification
  callback. In order to exploit this issue the Apache server would need to
  be configured to use a malicious certificate revocation list (CRL). The
  Common Vulnerabilities and Exposures project (cve.mitre.org) assigned the
  name CVE-2005-1268 to this issue.

  Users of Apache httpd should update to these errata packages that contain
  backported patches to correct these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2005-582.html
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
if ( rpm_check( reference:"httpd-2.0.46-46.2.ent", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"httpd-devel-2.0.46-46.2.ent", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mod_ssl-2.0.46-46.2.ent", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"httpd-2.0.52-12.1.ent", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"httpd-devel-2.0.52-12.1.ent", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"httpd-manual-2.0.52-12.1.ent", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"httpd-suexec-2.0.52-12.1.ent", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mod_ssl-2.0.52-12.1.ent", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"httpd-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2005-1268", value:TRUE);
 set_kb_item(name:"CVE-2005-2088", value:TRUE);
}
if ( rpm_exists(rpm:"httpd-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2005-1268", value:TRUE);
 set_kb_item(name:"CVE-2005-2088", value:TRUE);
}

set_kb_item(name:"RHSA-2005-582", value:TRUE);
