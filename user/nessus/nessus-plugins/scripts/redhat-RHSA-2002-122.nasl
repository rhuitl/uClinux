#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12633);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2002-0384");

 name["english"] = "RHSA-2002-122: gaim";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated gaim packages are now available for Red Hat Linux Advanced Server.
  These updates fix a buffer overflow in the Jabber plug-in module.

  Gaim is an instant messaging client based on the published TOC protocol
  from AOL. Versions of gaim prior to 0.58 contain a buffer overflow in the
  Jabber plug-in module.

  Users of gaim should update to these errata packages containing gaim
  0.59 which is not vulnerable to this issue.

  Please note that gaim version 0.57 had an additional security problem
  which has been fixed in version 0.58 (CVE-2002-0377); however, Red Hat
  Linux Advanced Server did not ship with version 0.57 and was not vulnerable
  to this issue.

  [update 14 Aug 2002]
  Previous packages pushed were not signed, this update replaces the packages
  with signed versions




Solution : http://rhn.redhat.com/errata/RHSA-2002-122.html
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
if ( rpm_check( reference:"gaim-0.59-0.2.1.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"gaim-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2002-0384", value:TRUE);
}

set_kb_item(name:"RHSA-2002-122", value:TRUE);
