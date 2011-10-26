#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(22202);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2006-3918");

 name["english"] = "RHSA-2006-0618: apache";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated Apache httpd packages that correct a security issue are now
  available for Red Hat Enterprise Linux 2.1.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  The Apache HTTP Server is a popular Web server available for free.

  A bug was found in Apache where an invalid Expect header sent to the server
  was returned to the user in an unescaped error message. This could
  allow an attacker to perform a cross-site scripting attack if a victim was
  tricked into connecting to a site and sending a carefully crafted Expect
  header. (CVE-2006-3918)

  While a web browser cannot be forced to send an arbitrary Expect header by
  a third-party attacker, it was recently discovered that certain versions of
  the Flash plugin can manipulate request headers. If users running such
  versions can be persuaded to load a web page with a malicious Flash applet,
  a cross-site scripting attack against the server may be possible.

  Users of Apache should upgrade to these updated packages, which contain a
  backported patch to correct this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2006-0618.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the apache packages";
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
if ( rpm_check( reference:"apache-1.3.27-11.ent", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"apache-devel-1.3.27-11.ent", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"apache-manual-1.3.27-11.ent", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"apache-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2006-3918", value:TRUE);
}

set_kb_item(name:"RHSA-2006-0618", value:TRUE);
