#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12363);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2002-1155");

 name["english"] = "RHSA-2003-050: kon";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  A buffer overflow in kon2 allows local users to obtain root privileges.

  KON is a Kanji emulator for the console. There is a buffer overflow
  vulnerability in the command line parsing code portion of the kon program
  up to and including version 0.3.9b. This vulnerability, if appropriately
  exploited, can lead to local users being able to gain escalated (root)
  privileges.

  All users of kon2 should update to these errata packages which contain a
  patch to fix this vulnerability.

  Red Hat would like to thank Janusz Niewiadomski for notifying us of this
  issue.




Solution : http://rhn.redhat.com/errata/RHSA-2003-050.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the kon packages";
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
if ( rpm_check( reference:"kon2-0.3.9b-14.as21.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kon2-fonts-0.3.9b-14.as21.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"kon-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2002-1155", value:TRUE);
}

set_kb_item(name:"RHSA-2003-050", value:TRUE);
