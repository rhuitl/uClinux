#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12310);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2002-0653");

 name["english"] = "RHSA-2002-136: mod_ssl";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated mod_ssl packages are now available for Red Hat Advanced Server.
  These updates incorporate a fix for an incorrect bounds check in versions
  of mod_ssl up to and including version 2.8.9.

  The mod_ssl module provides strong cryptography for the Apache Web
  server via the Secure Sockets Layer (SSL) and Transport Layer Security
  (TLS) protocols. Versions of mod_ssl prior to 2.8.10 are subject to a
  single NULL overflow that can cause arbitrary code execution.

  In order to exploit this vulnerability, the Apache Web server has to be
  configured to allow overriding of configuration settings on a per-directory
  basis, and untrusted local users must be able to modify a directory in
  which the server is configured to allow overriding. The local attacker may
  then become the user that Apache is running as (usually \'www\' or \'nobody\').

  Note that regardless of this bug, local users can obtain the same
  privileges if the server is configured to allow them to create CGI scripts
  which run as the Web server user, or if PHP is enabled but not configured
  in "safe mode".

  The errata packages contain versions of mod_ssl that have been patched and
  are not vulnerable to this issue.

  Please note that you must restart the httpd daemon to use the updated
  module. For instructions on doing this, see the bottom of the Solutions
  section below.




Solution : http://rhn.redhat.com/errata/RHSA-2002-136.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the mod_ssl packages";
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
if ( rpm_check( reference:"mod_ssl-2.8.7-6", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"mod_ssl-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2002-0653", value:TRUE);
}

set_kb_item(name:"RHSA-2002-136", value:TRUE);
