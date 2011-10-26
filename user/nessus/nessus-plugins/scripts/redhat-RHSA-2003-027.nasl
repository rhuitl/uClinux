#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12355);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2002-1467", "CVE-2002-0846");

 name["english"] = "RHSA-2003-027: netscape";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated Netscape 4.8 packages fixing various bugs and vulnerabilities are
  now available.

  Netscape is a suite of Internet utilities including a Web browser, email
  client, and Usenet news reader.

  Netscape version 4.8 contains various bugfixes and updates.

  Note that Macromedia Flash is no longer included as of this update. The
  recommended Macromedia Flash with security fixes no longer supports
  Netscape 4.x. The security issues that affected the Macromedia Flash
  player include CVE-2002-0846 and CVE-2002-1467.

  It is recommended that all Netscape Communicator and Netscape Navigator
  users upgrade to these errata packages.




Solution : http://rhn.redhat.com/errata/RHSA-2003-027.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the netscape packages";
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
if ( rpm_check( reference:"netscape-common-4.8-1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"netscape-communicator-4.8-1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"netscape-navigator-4.8-1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"netscape-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2002-1467", value:TRUE);
 set_kb_item(name:"CVE-2002-0846", value:TRUE);
}

set_kb_item(name:"RHSA-2003-027", value:TRUE);
