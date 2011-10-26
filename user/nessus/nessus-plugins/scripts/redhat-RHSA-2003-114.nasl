#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12383);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2003-0084");

 name["english"] = "RHSA-2003-114: mod_auth_any";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated mod_auth_any packages are available for Red Hat Enterprise Linux.
  These updated packages fix vulnerabilities associated with the manner in
  which mod_auth_any escapes shell arguments when calling external programs.

  The Web server module mod_auth_any allows the Apache httpd server to
  call arbitrary external programs to verify user passwords.

  Vulnerabilities have been found in versions of mod_auth_any included in Red
  Hat Enterprise Linux concerning the method by which mod_auth_any escapes
  shell arguments when calling external programs. These vulnerabilities
  allow remote attackers to run arbitrary commands as the user under which
  the Web server is running. The Common Vulnerabilities and Exposures
  project (cve.mitre.org) has assigned the name CVE-2003-0084 to these
  issues.

  All users are advised to upgrade to these errata packages, which change the
  method by which external programs are invoked and, therefore, make these
  programs invulnerable to these issues.

  Red Hat would like to thank Daniel Jarboe and Maneesh Sahani for bringing
  these issues to our attention.




Solution : http://rhn.redhat.com/errata/RHSA-2003-114.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the mod_auth_any packages";
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
if ( rpm_check( reference:"mod_auth_any-1.2.2-2", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"mod_auth_any-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2003-0084", value:TRUE);
}

set_kb_item(name:"RHSA-2003-114", value:TRUE);
