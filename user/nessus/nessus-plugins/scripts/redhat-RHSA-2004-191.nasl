#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12496);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2004-0398");

 name["english"] = "RHSA-2004-191: cadaver";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  An updated cadaver package is now available that fixes a vulnerability in
  neon which could be exploitable by a malicious DAV server.

  cadaver is a command-line WebDAV client that uses inbuilt code from neon,
  an HTTP and WebDAV client library.

  Stefan Esser discovered a flaw in the neon library which allows a heap
  buffer overflow in a date parsing routine. An attacker could create
  a malicious WebDAV server in such a way as to allow arbitrary code
  execution on the client should a user connect to it using cadaver. The
  Common Vulnerabilities and Exposures project (cve.mitre.org) has assigned
  the name CVE-2004-0398 to this issue.

  Users of cadaver are advised to upgrade to this updated package, which
  contains a patch correcting this issue.

  This issue does not affect Red Hat Enterprise Linux 3.




Solution : http://rhn.redhat.com/errata/RHSA-2004-191.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the cadaver packages";
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
if ( rpm_check( reference:"cadaver-0.22.1-1.0", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"cadaver-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2004-0398", value:TRUE);
}

set_kb_item(name:"RHSA-2004-191", value:TRUE);
