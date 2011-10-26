#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12308);
 script_version ("$Revision: 1.6 $");
 script_cve_id("CVE-2002-0713", "CVE-2002-0715", "CVE-2002-0714");

 name["english"] = "RHSA-2002-130: squid";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  New Squid packages are available which fix various issues.

  Squid is a high-performance proxy caching server. The following summary
  describes the various issues found and fixed:

  Several buffer overflows have been found in the MSTN auth helper
  (msnt_auth) when configured to use denyusers or allowusers access control
  files.

  Several buffer overflows were found in the gopher client of Squid. It
  could be possible for a malicious gopher server to cause Squid to crash.

  A problem was found in the handling of the FTP data channel, possibly
  allowing abuse of the FTP proxy to bypass firewall rules or inject false
  FTP replies.

  Several possible buffer overflows were found in the code parsing FTP
  directories, which potentially allow for an untrusted FTP server to crash
  Squid.

  Thanks go to Olaf Kirch and the Squid team for notifying us of the
  problems and to the Squid team for providing patches.

  All users of Squid are advised to upgrade to these errata packages which
  contain patches to correct each of these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2002-130.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the squid packages";
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
if ( rpm_check( reference:"squid-2.4.STABLE6-6.7.3", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"squid-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2002-0713", value:TRUE);
 set_kb_item(name:"CVE-2002-0715", value:TRUE);
 set_kb_item(name:"CVE-2002-0714", value:TRUE);
}

set_kb_item(name:"RHSA-2002-130", value:TRUE);
