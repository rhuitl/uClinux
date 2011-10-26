#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12303);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2002-0382");

 name["english"] = "RHSA-2002-124: xchat";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  A security issue in XChat allows a malicious server to execute arbitrary
  commands.

  XChat is a popular cross-platform IRC client.

  Versions of XChat prior to 1.8.9 do not filter the response from an IRC
  server when a /dns query is executed. Because XChat resolves hostnames by
  passing the configured resolver and hostname to a shell, an IRC server may
  return a maliciously formatted response that executes arbitrary commands
  with the privileges of the user running XChat.

  All users of XChat are advised to update to these errata packages
  containing XChat version 1.8.9 which is not vulnerable to this issue.

  [update 14 Aug 2002]
  Previous packages pushed were not signed, this update replaces the packages
  with signed versions




Solution : http://rhn.redhat.com/errata/RHSA-2002-124.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the xchat packages";
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
if ( rpm_check( reference:"xchat-1.8.9-1.21as.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"xchat-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2002-0382", value:TRUE);
}

set_kb_item(name:"RHSA-2002-124", value:TRUE);
