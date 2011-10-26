#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12385);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2003-b-0003");
 script_version ("$Revision: 1.6 $");
 script_cve_id("CVE-2003-0161");

 name["english"] = "RHSA-2003-121: sendmail";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated Sendmail packages are available to fix a vulnerability that
  allows local and possibly remote attackers to gain root privileges.

  Sendmail is a widely used Mail Transport Agent (MTA) which is included
  in all Red Hat Enterprise Linux distributions.

  There is a vulnerability in Sendmail versions 8.12.8 and prior. The
  address parser performs insufficient bounds checking in certain conditions
  due to a char to int conversion, making it possible for an attacker to
  take control of the application. Although no exploit currently exists,
  this issue is probably locally exploitable and may be remotely exploitable.

  All users are advised to update to these erratum packages containing a
  backported patch which corrects these vulnerabilities.

  Red Hat would like to thank Michal Zalewski for finding and reporting this
  issue.




Solution : http://rhn.redhat.com/errata/RHSA-2003-121.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the sendmail packages";
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
if ( rpm_check( reference:"sendmail-8.11.6-26.72", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-cf-8.11.6-26.72", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-devel-8.11.6-26.72", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-doc-8.11.6-26.72", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"sendmail-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2003-0161", value:TRUE);
}

set_kb_item(name:"RHSA-2003-121", value:TRUE);
