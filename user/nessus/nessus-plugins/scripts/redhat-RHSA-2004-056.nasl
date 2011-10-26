#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12463);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2004-0080");

 name["english"] = "RHSA-2004-056: util";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated util-linux packages that fix an information leak in the login
  program are now available.

  The util-linux package contains a large variety of low-level system
  utilities that are necessary for a Linux system to function.

  In some situations, the login program could use a pointer that had been
  freed and reallocated. This could cause unintentional data leakage.

  Note: Red Hat Enterprise Linux 3 is not vulnerable to this issue.

  It is recommended that all users upgrade to these updated packages, which
  are not vulnerable to this issue.

  Red Hat would like to thank Matthew Lee of Fleming College for finding and
  reporting this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2004-056.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the util packages";
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
if ( rpm_check( reference:"util-linux-2.11f-20.4", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"util-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2004-0080", value:TRUE);
}

set_kb_item(name:"RHSA-2004-056", value:TRUE);
