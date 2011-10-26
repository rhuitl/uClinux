#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12504);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2004-0541");

 name["english"] = "RHSA-2004-242: squid";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  An updated squid package that fixes a security vulnerability in
  the NTLM authentication helper is now available.

  Squid is a full-featured Web proxy cache.

  A buffer overflow was found within the NTLM authentication helper
  routine. If Squid is configured to use the NTLM authentication helper,
  a remote attacker could potentially execute arbitrary code by sending a
  lengthy password. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CVE-2004-0541 to this issue.

  Note: The NTLM authentication helper is not enabled by default in Red Hat
  Enterprise Linux 3. Red Hat Enterprise Linux 2.1 is not vulnerable to this
  issue as it shipped with a version of Squid which did not contain the
  helper.

  Users of Squid should update to this errata package which contains a
  backported patch that is not vulnerable to this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2004-242.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the squid packages";
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
if ( rpm_check( reference:"squid-2.5.STABLE3-6.3E", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"squid-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2004-0541", value:TRUE);
}

set_kb_item(name:"RHSA-2004-242", value:TRUE);
