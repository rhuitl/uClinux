#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20045);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-1704");

 name["english"] = "RHSA-2005-763: binutils";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  An updated binutils package that fixes minor security issues is now
  available.

  This update has been rated as having low security impact by the Red Hat
  Security Response Team.

  Binutils is a collection of utilities used for the creation of executable
  code. A number of bugs were found in various binutils tools.

  Several integer overflow bugs were found in binutils. If a user is tricked
  into processing a specially crafted executable with utilities such as
  readelf, size, strings, objdump, or nm, it may allow the execution of
  arbitrary code as the user running the utility. The Common Vulnerabilities
  and Exposures project (cve.mitre.org) has assigned the name CVE-2005-1704
  to this issue.

  All users of binutils should upgrade to this updated package, which
  contains backported patches to resolve these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2005-763.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the binutils packages";
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
if ( rpm_check( reference:"binutils-2.11.90.0.8-12.5", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"binutils-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2005-1704", value:TRUE);
}

set_kb_item(name:"RHSA-2005-763", value:TRUE);
