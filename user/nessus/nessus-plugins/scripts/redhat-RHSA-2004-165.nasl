#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12488);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2004-t-0004");
 script_version ("$Revision: 1.6 $");
 script_cve_id("CVE-2004-0155", "CVE-2004-0164", "CVE-2004-0403");

 name["english"] = "RHSA-2004-165: ipsec";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  An updated ipsec-tools package that fixes vulnerabilities in racoon (the
  ISAKMP daemon) is now available.

  IPSEC uses strong cryptography to provide both authentication and
  encryption services.

  With versions of ipsec-tools prior to 0.2.3, it was possible for an
  attacker to cause unauthorized deletion of SA (Security Associations.)
  The Common Vulnerabilities and Exposures project (cve.mitre.org) has
  assigned the name CVE-2004-0164 to this issue.

  With versions of ipsec-tools prior to 0.2.5, the RSA signature on x.509
  certificates was not properly verified when using certificate based
  authentication. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CVE-2004-0155 to this issue.

  When ipsec-tools receives an ISAKMP header, it will attempt to allocate
  sufficient memory for the entire ISAKMP message according to the header\'s
  length field. If an attacker crafts an ISAKMP header with a extremely large
  value in the length field, racoon may exceed operating system resource
  limits and be terminated, resulting in a denial of service. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CVE-2004-0403 to this issue.

  User of IPSEC should upgrade to this updated package, which contains
  ipsec-tools version 0.25 along with a security patch for CVE-2004-0403
  which resolves all these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2004-165.html
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
if ( rpm_check( reference:"ipsec-tools-0.2.5-0.4", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"ipsec-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2004-0155", value:TRUE);
 set_kb_item(name:"CVE-2004-0164", value:TRUE);
 set_kb_item(name:"CVE-2004-0403", value:TRUE);
}

set_kb_item(name:"RHSA-2004-165", value:TRUE);
