#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12636);
 script_version ("$Revision: 1.6 $");
 script_cve_id("CVE-2004-0488", "CVE-2004-0493");

 name["english"] = "RHSA-2004-342: httpd";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated httpd packages that fix a buffer overflow in mod_ssl and a remotely
  triggerable memory leak are now available.

  The Apache HTTP server is a powerful, full-featured, efficient, and
  freely-available Web server.

  A stack buffer overflow was discovered in mod_ssl that could be triggered
  if using the FakeBasicAuth option. If mod_ssl was sent a client certificate
  with a subject DN field longer than 6000 characters, a stack overflow
  occured if FakeBasicAuth had been enabled. In order to exploit this issue
  the carefully crafted malicious certificate would have had to be signed by
  a Certificate Authority which mod_ssl is configured to trust. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CVE-2004-0488 to this issue.

  A remotely triggered memory leak in the Apache HTTP Server earlier than
  version 2.0.50 was also discovered. This allowed a remote attacker to
  perform a denial of service attack against the server by forcing it to
  consume large amounts of memory. The Common Vulnerabilities and Exposures
  project (cve.mitre.org) has assigned the name CVE-2004-0493 to this issue.

  Users of the Apache HTTP server should upgrade to these updated packages,
  which contain backported patches that address these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2004-342.html
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
if ( rpm_check( reference:"httpd-2.0.46-32.ent.3", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"httpd-devel-2.0.46-32.ent.3", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mod_ssl-2.0.46-32.ent.3", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"httpd-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2004-0488", value:TRUE);
 set_kb_item(name:"CVE-2004-0493", value:TRUE);
}

set_kb_item(name:"RHSA-2004-342", value:TRUE);
