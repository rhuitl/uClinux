#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20733);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2005-3352");

 name["english"] = "RHSA-2006-0158: apache";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated Apache httpd packages that correct a security issue are now
  available for Red Hat Enterprise Linux 2.1.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  The Apache HTTP Server is a popular and freely-available Web server.

  A flaw in mod_imap when using the Referer directive with image maps was
  discovered. With certain site configurations, a remote attacker could
  perform a cross-site scripting attack if a victim can be forced to visit a
  malicious URL using certain web browsers. The Common Vulnerabilities and
  Exposures project assigned the name CVE-2005-3352 to this issue.

  Users of apache should upgrade to these updated packages, which contain
  a backported patch to correct this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2006-0158.html
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
if ( rpm_check( reference:"apache-1.3.27-10.ent", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"apache-devel-1.3.27-10.ent", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"apache-manual-1.3.27-10.ent", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"apache-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2005-3352", value:TRUE);
}

set_kb_item(name:"RHSA-2006-0158", value:TRUE);
