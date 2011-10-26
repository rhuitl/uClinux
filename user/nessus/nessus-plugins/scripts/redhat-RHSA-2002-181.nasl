#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12322);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2002-0855");

 name["english"] = "RHSA-2002-181: mailman";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated mailman packages are now available for Red Hat Linux Advanced
  Server. These updates close a cross-site scripting vulnerability present
  in mailman versions prior to version 2.0.12.

  Mailman versions prior to 2.0.12 contain a cross-site scripting
  vulnerability in the processing of invalid requests to edit a subscriber\'s
  list subscription options.




Solution : http://rhn.redhat.com/errata/RHSA-2002-181.html
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
if ( rpm_check( reference:"mailman-2.0.13-1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"mailman-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2002-0855", value:TRUE);
}

set_kb_item(name:"RHSA-2002-181", value:TRUE);
