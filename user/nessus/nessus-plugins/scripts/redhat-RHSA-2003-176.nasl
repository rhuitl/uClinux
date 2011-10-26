#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12396);
 script_version ("$Revision: 1.6 $");
 script_cve_id("CVE-2003-0255");

 name["english"] = "RHSA-2003-176: gnupg";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated gnupg packages are now available which correct a bug in the GnuPG
  key validation functions.

  The GNU Privacy Guard (GnuPG) is a utility for encrypting data and
  creating digital signatures.

  When evaluating trust values for the UIDs assigned to a given key,
  GnuPG versions earlier than 1.2.2 would incorrectly associate the trust
  value of the UID having the highest trust value with every UID assigned to
  this key. This would prevent an expected warning message from being
  generated.

  All users are advised to upgrade to these errata packages which include an
  update to GnuPG 1.0.7 containing patches from the GnuPG
  development team to correct this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2003-176.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the gnupg packages";
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
if ( rpm_check( reference:"gnupg-1.0.7-7.2.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"gnupg-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2003-0255", value:TRUE);
}

set_kb_item(name:"RHSA-2003-176", value:TRUE);
