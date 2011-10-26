#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12323);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2002-0989");

 name["english"] = "RHSA-2002-191: gaim";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated gaim packages are now available for Red Hat Linux Advanced Server.
  These updates fix a vulnerability in the default URL handler.

  Gaim is an all-in-one instant messaging client that lets you use a number
  of
  messaging protocols such as AIM, ICQ, and Yahoo, all at once.

  Versions of gaim prior to 0.59.1 contain a bug in the URL handler of
  the manual browser option. A link can be carefully crafted to contain
  an arbitrary shell script which will be executed if the user clicks on
  the link.

  Users of gaim should update to these errata packages containing gaim
  0.59.1 which is not vulnerable to this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2002-191.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the gaim packages";
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
if ( rpm_check( reference:"gaim-0.59.1-0.2.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"gaim-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2002-0989", value:TRUE);
}

set_kb_item(name:"RHSA-2002-191", value:TRUE);
