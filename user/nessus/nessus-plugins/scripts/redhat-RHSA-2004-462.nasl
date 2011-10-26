#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(15410);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2004-0832");

 name["english"] = "RHSA-2004-462: squid";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  An updated squid package that fixes a security vulnerability in the NTLM
  authentication helper is now available.

  Squid is a full-featured Web proxy cache.

  An out of bounds memory read bug was found within the NTLM authentication
  helper routine. If Squid is configured to use the NTLM authentication
  helper, a remote attacker could send a carefully crafted NTLM
  authentication packet and cause Squid to crash. The Common Vulnerabilities
  and Exposures project (cve.mitre.org) has assigned the name CVE-2004-0832
  to this issue.

  Note: The NTLM authentication helper is not enabled by default in Red Hat
  Enterprise Linux 3. Red Hat Enterprise Linux 2.1 is not vulnerable to this
  issue as it shipped with a version of Squid which did not contain the
  vulnerable helper.

  Users of Squid should update to this erratum package, which contains a
  backported patch and is not vulnerable to this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2004-462.html
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
if ( rpm_check( reference:"squid-2.5.STABLE3-6.3E.1", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"squid-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2004-0832", value:TRUE);
}

set_kb_item(name:"RHSA-2004-462", value:TRUE);
