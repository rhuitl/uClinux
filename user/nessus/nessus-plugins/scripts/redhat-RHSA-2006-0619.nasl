#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(22224);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2006-3918");

 name["english"] = "RHSA-2006-0619: httpd";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated Apache httpd packages that correct security issues and resolve bugs
  are now available for Red Hat Enterprise Linux 3 and 4.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  The Apache HTTP Server is a popular Web server available for free.

  A bug was found in Apache where an invalid Expect header sent to the server
  was returned to the user in an unescaped error message. This could
  allow an attacker to perform a cross-site scripting attack if a victim was
  tricked into connecting to a site and sending a carefully crafted Expect
  header. (CVE-2006-3918)

  While a web browser cannot be forced to send an arbitrary Expect
  header by a third-party attacker, it was recently discovered that
  certain versions of the Flash plugin can manipulate request headers.
  If users running such versions can be persuaded to load a web page
  with a malicious Flash applet, a cross-site scripting attack against
  the server may be possible.

  On Red Hat Enterprise Linux 3 and 4 systems, due to an unrelated issue in
  the handling of malformed Expect headers, the page produced by the
  cross-site scripting attack will only be returned after a timeout expires
  (2-5 minutes by default) if not first canceled by the user.

  Users of httpd should update to these erratum packages, which contain a
  backported patch to correct these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2006-0619.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the httpd packages";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 family["english"] = "Red Hat Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"httpd-2.0.46-61.ent", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"httpd-devel-2.0.46-61.ent", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mod_ssl-2.0.46-61.ent", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"httpd-2.0.52-28.ent", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"httpd-devel-2.0.52-28.ent", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"httpd-manual-2.0.52-28.ent", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"httpd-suexec-2.0.52-28.ent", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mod_ssl-2.0.52-28.ent", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"httpd-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2006-3918", value:TRUE);
}
if ( rpm_exists(rpm:"httpd-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2006-3918", value:TRUE);
}

set_kb_item(name:"RHSA-2006-0619", value:TRUE);
