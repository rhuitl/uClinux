#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12333);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2002-0180");

 name["english"] = "RHSA-2002-255: webalizer";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated Webalizer packages are available for Red Hat Linux Advanced Server
  2.1 which fix an obscure buffer overflow bug in the DNS resolver code.

  [Updated 13 Jan 2003]
  Added fixed packages for the Itanium (IA64) architecture.

  [Updated 06 Feb 2003]
  Added fixed packages for Advanced Workstation 2.1

  Webalizer is a Web server log file analysis program which produces
  detailed usage reports in HTML format.

  A buffer overflow in Webalizer versions prior to 2.01-10, when configured
  to use reverse DNS lookups, may allow remote attackers to execute arbitrary
  code by connecting to the monitored Web server from an IP address that
  resolves to a long hostname.

  Users of Webalizer are advised to upgrade to these errata packages which
  contain Webalizer version 2.01-09 with backported security and bug fix
  patches.




Solution : http://rhn.redhat.com/errata/RHSA-2002-255.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the webalizer packages";
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
if ( rpm_check( reference:"webalizer-2.01_09-1.72", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"webalizer-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2002-0180", value:TRUE);
}

set_kb_item(name:"RHSA-2002-255", value:TRUE);
