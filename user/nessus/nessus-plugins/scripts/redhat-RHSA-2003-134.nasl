#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12386);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2003-0124");

 name["english"] = "RHSA-2003-134: man";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated man packages fix a minor security vulnerability.

  The man package includes tools for finding information and documentation
  about commands on a system.

  Versions of man before 1.51 have a bug where a malformed man file can cause
  a program named "unsafe" to be run. To exploit this vulnerability a local
  attacker would need to be able to get a victim to run man on a carefully
  crafted man file, and for the attacker to be able to create a file called
  "unsafe" that will be on the victim\'s default path.

  Users of man can upgrade to these erratum packages which contain a patch to
  correct this vulnerability. These erratum packages also contain fixes for
  a number of other bugs.




Solution : http://rhn.redhat.com/errata/RHSA-2003-134.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the man packages";
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
if ( rpm_check( reference:"man-1.5i2-7.21as.0", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"man-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2003-0124", value:TRUE);
}

set_kb_item(name:"RHSA-2003-134", value:TRUE);
