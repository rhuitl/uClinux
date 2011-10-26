#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(15990);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2004-1010");

 name["english"] = "RHSA-2004-634: zip";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  An updated zip package that fixes a buffer overflow vulnerability is now
  available.

  The zip program is an archiving utility which can create ZIP-compatible
  archives.

  A buffer overflow bug has been discovered in zip when handling long file
  names. An attacker could create a specially crafted path which could
  cause zip to crash or execute arbitrary instructions. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CVE-2004-1010 to this issue.

  Users of zip should upgrade to this updated package, which contains
  backported patches and is not vulnerable to this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2004-634.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the zip packages";
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
if ( rpm_check( reference:"zip-2.3-10.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"zip-2.3-16.1", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"zip-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2004-1010", value:TRUE);
}
if ( rpm_exists(rpm:"zip-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2004-1010", value:TRUE);
}

set_kb_item(name:"RHSA-2004-634", value:TRUE);
