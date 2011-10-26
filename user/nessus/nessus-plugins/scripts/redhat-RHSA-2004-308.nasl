#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13854);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2004-0607");

 name["english"] = "RHSA-2004-308: ipsec";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  An updated ipsec-tools package that fixes verification of X.509
  certificates in racoon is now available.

  IPSEC uses strong cryptography to provide both authentication and
  encryption services.

  When configured to use X.509 certificates to authenticate remote hosts,
  ipsec-tools versions 0.3.3 and earlier will attempt to verify that host
  certificate, but will not abort the key exchange if verification fails.
  The Common Vulnerabilities and Exposures project (cve.mitre.org) has
  assigned the name CVE-2004-0607 to this issue.

  Users of ipsec-tools should upgrade to this updated package which contains
  a backported security patch and is not vulnerable to this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2004-308.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the ipsec packages";
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
if ( rpm_check( reference:"ipsec-tools-0.2.5-0.5", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"ipsec-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2004-0607", value:TRUE);
}

set_kb_item(name:"RHSA-2004-308", value:TRUE);
