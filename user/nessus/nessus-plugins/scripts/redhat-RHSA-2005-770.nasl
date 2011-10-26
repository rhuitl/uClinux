#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20047);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2004-2392");

 name["english"] = "RHSA-2005-770: libuser";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated libuser packages that fix various security issues are now
  available.

  This update has been rated as having low security impact by the Red Hat
  Security Response Team.

  The libuser library implements a standardized interface for manipulating
  and administering user and group accounts. The library uses pluggable
  back-ends to interface to its data sources. Sample applications that are
  modeled after applications from the shadow password suite are included in
  the package.

  Several denial of service bugs were discovered in libuser. Under certain
  conditions it is possible for an application linked against libuser to
  crash or operate irregularly. The Common Vulnerabilities and Exposures
  project (cve.mitre.org) has assigned the name CVE-2004-2392 to these
  issues.

  All users of libuser are advised to upgrade to these updated packages,
  which contain a backported fix and are not vulnerable to these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2005-770.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the libuser packages";
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
if ( rpm_check( reference:"libuser-0.32-1.el2.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libuser-devel-0.32-1.el2.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"libuser-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2004-2392", value:TRUE);
}

set_kb_item(name:"RHSA-2005-770", value:TRUE);
