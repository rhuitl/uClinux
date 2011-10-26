#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12491);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2004-0234", "CVE-2004-0235");

 name["english"] = "RHSA-2004-178: lha";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  An updated LHA package that fixes several security vulnerabilities is now
  available.

  LHA is an archiving and compression utility for LHarc format archives.

  Ulf Harnhammar discovered two stack buffer overflows and two directory
  traversal flaws in LHA. An attacker could exploit the buffer overflows by
  creating a carefully crafted LHA archive in such a way that arbitrary code
  would be executed when the archive is tested or extracted by a victim. The
  Common Vulnerabilities and Exposures project (cve.mitre.org) has
  assigned the name CVE-2004-0234 to this issue. An attacker could exploit
  the directory traversal issues to create files as the victim outside of the
  expected directory. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CVE-2004-0235 to this issue.

  Users of LHA should update to this updated package which contains
  backported patches not vulnerable to these issues.

  Red Hat would like to thank Ulf Harnhammar for disclosing and providing
  test cases and patches for these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2004-178.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the lha packages";
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
if ( rpm_check( reference:"lha-1.00-17.2", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"lha-1.14i-10.2", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"lha-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2004-0234", value:TRUE);
 set_kb_item(name:"CVE-2004-0235", value:TRUE);
}
if ( rpm_exists(rpm:"lha-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2004-0234", value:TRUE);
 set_kb_item(name:"CVE-2004-0235", value:TRUE);
}

set_kb_item(name:"RHSA-2004-178", value:TRUE);
