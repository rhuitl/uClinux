#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12429);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2003-0855");

 name["english"] = "RHSA-2003-312: pan";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated Pan packages that close a denial of service vulnerability are now
  available.

  Pan is a Gnome/GTK+ newsreader.

  A bug in Pan versions prior to 0.13.4 can cause Pan to crash when parsing
  an article header containing a very long author email address. This bug
  causes a denial of service (crash), but cannot be exploited further. The
  Common Vulnerabilities and Exposures project (cve.mitre.org) has
  assigned the name CVE-2003-0855 to this issue.

  Users of Pan are advised to upgrade to these erratum packages, which
  contain a backported patch correcting this issue.

  Red Hat would like to thank Kasper Dupont for alerting us to this issue and
  to Charles Kerr for providing the patch.




Solution : http://rhn.redhat.com/errata/RHSA-2003-312.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the pan packages";
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
if ( rpm_check( reference:"pan-0.9.7-3", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"pan-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2003-0855", value:TRUE);
}

set_kb_item(name:"RHSA-2003-312", value:TRUE);
