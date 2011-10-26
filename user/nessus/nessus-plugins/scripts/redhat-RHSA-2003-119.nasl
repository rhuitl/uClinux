#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12384);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2002-1363");

 name["english"] = "RHSA-2003-119: micq";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated mICQ packages are available which fix a remote crash.

  mICQ is an online messaging and conferencing program.

  mICQ 0.4.9 and earlier allows remote attackers to cause a denial of service
  (crash) via malformed ICQ message types without a 0xFE separator character.

  Users of mICQ are advised to upgrade to these erratum packages containing
  mICQ version 0.4.10.2 which is not vulnerable to this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2003-119.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the micq packages";
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
if ( rpm_check( reference:"micq-0.4.10.2-1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"micq-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2002-1363", value:TRUE);
}

set_kb_item(name:"RHSA-2003-119", value:TRUE);
