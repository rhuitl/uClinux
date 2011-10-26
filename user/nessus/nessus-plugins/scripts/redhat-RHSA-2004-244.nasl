#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12505);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2004-0536");

 name["english"] = "RHSA-2004-244: tripwire";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated Tripwire packages that fix a format string security vulnerability
  are now available.

  Tripwire is a system integrity assessment tool.

  Paul Herman discovered a format string vulnerability in Tripwire version
  2.3.1 and earlier. If Tripwire is configured to send reports via email, a
  local user could gain privileges by creating a carefully crafted file. The
  Common Vulnerabilities and Exposures project (cve.mitre.org) has assigned
  the name CVE-2004-0536 to this issue.

  Users of Tripwire are advised to upgrade to this erratum package which
  contains a backported security patch to correct this issue. The erratum
  package also contains some minor bug fixes.




Solution : http://rhn.redhat.com/errata/RHSA-2004-244.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the tripwire packages";
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
if ( rpm_check( reference:"tripwire-2.3.1-18", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"tripwire-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2004-0536", value:TRUE);
}

set_kb_item(name:"RHSA-2004-244", value:TRUE);
