#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12305);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2002-0392");

 name["english"] = "RHSA-2002-126: apache";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  The Apache Web server contains a security vulnerability which can be used
  to launch a denial of service (DoS) attack or, in some cases, allow remote
  code execution.

  Versions of the Apache Web server up to and including 1.3.24 contain a bug
  in the routines which deal with requests using "chunked" encoding.
  A carefully crafted invalid request can cause an Apache child process to
  call the memcpy() function in a way that will write past the end of its
  buffer, corrupting the stack. On some platforms this can be remotely
  exploited -- allowing arbitrary code to be run on the server.

  The Common Vulnerabilities and Exposures project (cve.mitre.org) has
  assigned the name CVE-2002-0392 to this issue.

  All users of Apache should update to these errata packages to correct this
  security issue.




Solution : http://rhn.redhat.com/errata/RHSA-2002-126.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the apache packages";
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
if ( rpm_check( reference:"apache-1.3.23-15", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"apache-devel-1.3.23-15", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"apache-manual-1.3.23-15", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"apache-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2002-0392", value:TRUE);
}

set_kb_item(name:"RHSA-2002-126", value:TRUE);
