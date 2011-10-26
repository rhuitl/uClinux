#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12304);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2002-0388");

 name["english"] = "RHSA-2002-125: mailman";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated mailman packages are now available for Red Hat Linux Advanced
  Server.
  These updates resolve a cross-site scripting vulnerability present in
  versions of Mailman prior to 2.0.11.

  Two cross-site scripting vulnerabilities have been discovered in versions
  of Mailman prior to version 2.0.11.




Solution : http://rhn.redhat.com/errata/RHSA-2002-125.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the mailman packages";
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
if ( rpm_check( reference:"mailman-2.0.11-1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"mailman-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2002-0388", value:TRUE);
}

set_kb_item(name:"RHSA-2002-125", value:TRUE);
