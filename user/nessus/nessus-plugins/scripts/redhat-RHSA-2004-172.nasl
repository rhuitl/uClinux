#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12489);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2004-0226", "CVE-2004-0231", "CVE-2004-0232");

 name["english"] = "RHSA-2004-172: gmc";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated mc packages that resolve several buffer overflow vulnerabilities,
  one format string vulnerability and several temporary file creation
  vulnerabilities are now available.

  Midnight Commander (mc) is a visual shell much like a file manager.

  Several buffer overflows, several temporary file creation vulnerabilities,
  and one format string vulnerability have been discovered in Midnight
  Commander. These vulnerabilities were discovered mostly by Andrew V.
  Samoilov and Pavel Roskin. The Common Vulnerabilities and Exposures
  project (cve.mitre.org) has assigned the names CVE-2004-0226,
  CVE-2004-0231, and CVE-2004-0232 to these issues.

  Users should upgrade to these updated packages, which contain a backported
  patch to correct these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2004-172.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the gmc packages";
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
if ( rpm_check( reference:"gmc-4.5.51-36.3", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mc-4.5.51-36.3", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mcserv-4.5.51-36.3", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"gmc-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2004-0226", value:TRUE);
 set_kb_item(name:"CVE-2004-0231", value:TRUE);
 set_kb_item(name:"CVE-2004-0232", value:TRUE);
}

set_kb_item(name:"RHSA-2004-172", value:TRUE);
