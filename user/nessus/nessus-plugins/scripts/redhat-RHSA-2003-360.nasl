#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12435);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2003-0542");

 name["english"] = "RHSA-2003-360: apache";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated Apache packages that fix a minor security issue are now available
  for Red Hat Enterprise Linux.

  The Apache HTTP server is a powerful, full-featured, efficient, and
  freely-available Web server.

  An issue in the handling of regular expressions from configuration files
  was discovered in releases of the Apache HTTP Server version 1.3 prior to
  1.3.29. To exploit this issue an attacker would need to have the ability
  to write to Apache configuration files such as .htaccess or httpd.conf. A
  carefully-crafted configuration file can cause an exploitable buffer
  overflow and would allow the attacker to execute arbitrary code in the
  context of the server (in default configurations as the \'apache\' user).
  The Common Vulnerabilities and Exposures project (cve.mitre.org) has
  assigned the name CVE-2003-0542 to this issue.

  This update also includes an alternative version of the httpd binary which
  supports setting the MaxClients configuration directive to values above
  256.

  All users of the Apache HTTP Web Server are advised to upgrade to the
  applicable errata packages, which contain back-ported fixes correcting
  the above security issue.

  Note that the instructions in the "Solution" section of this errata contain
  additional steps required to complete the upgrade process.




Solution : http://rhn.redhat.com/errata/RHSA-2003-360.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the apache packages";
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
if ( rpm_check( reference:"apache-1.3.27-6.ent", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"apache-devel-1.3.27-6.ent", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"apache-manual-1.3.27-6.ent", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"apache-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2003-0542", value:TRUE);
}

set_kb_item(name:"RHSA-2003-360", value:TRUE);
