#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12357);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2002-1405");

 name["english"] = "RHSA-2003-030: lynx";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated Lynx packages fix an error in the way Lynx parses its command line
  arguments which can lead to faked headers being sent to a Web server.

  Lynx is a character-cell Web browser, suitable for running on terminals
  such as the VT100.

  Lynx constructs its HTTP queries from the command line (or WWW_HOME
  environment variable) without regard to special characters such as carriage
  returns or linefeeds. When given a URL containing such special characters,
  extra headers could be inserted into the request. This could cause scripts
  using Lynx to fetch data from the wrong site from servers with virtual
  hosting.

  Users of Lynx are advised to upgrade to these erratum packages which
  contain a patch to correct this isssue.




Solution : http://rhn.redhat.com/errata/RHSA-2003-030.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the lynx packages";
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
if ( rpm_check( reference:"lynx-2.8.4-18.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"lynx-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2002-1405", value:TRUE);
}

set_kb_item(name:"RHSA-2003-030", value:TRUE);
