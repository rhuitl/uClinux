#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12437);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2003-0967");

 name["english"] = "RHSA-2003-386: freeradius";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated FreeRADIUS packages are now available that fix a denial of service
  vulnerability.

  FreeRADIUS is an Internet authentication daemon, which implements the
  RADIUS protocol. It allows Network Access Servers (NAS boxes) to perform
  authentication for dial-up users.

  The rad_decode function in FreeRADIUS 0.9.2 and earlier allows remote
  attackers to cause a denial of service (crash) via a short RADIUS string
  attribute with a tag, which causes memcpy to be called with a -1 length
  argument, as demonstrated using the Tunnel-Password attribute. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CVE-2003-0967 to this issue.

  Users of FreeRADIUS are advised to upgrade to these erratum packages
  containing FreeRADIUS 0.9.3 which is not vulnerable to these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2003-386.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the freeradius packages";
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
if ( rpm_check( reference:"freeradius-0.9.3-1", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"freeradius-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2003-0967", value:TRUE);
}

set_kb_item(name:"RHSA-2003-386", value:TRUE);
