#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12351);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2003-0015");

 name["english"] = "RHSA-2003-013: cvs";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated CVS packages are now available for Red Hat Linux Advanced Server.
  These updates fix a vulnerability which would permit arbitrary command
  execution on servers configured to allow anonymous read-only access.

  [Updated 06 Feb 2003]
  Added fixed packages for Advanced Workstation 2.1

  CVS is a version control system frequently used to manage source code
  repositories. During an audit of the CVS sources, Stefan Esser discovered
  an exploitable double-free bug in the CVS server.

  On servers which are configured to allow anonymous read-only access, this
  bug could be used by anonymous users to gain write privileges. Users with
  CVS write privileges can then use the Update-prog and Checkin-prog features
  to execute arbitrary commands on the server.

  All users of CVS are advised to upgrade to these packages which
  contain patches to correct the double-free bug.

  Our thanks go to Stefan Esser of e-matters for reporting this issue to us.




Solution : http://rhn.redhat.com/errata/RHSA-2003-013.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the cvs packages";
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
if ( rpm_check( reference:"cvs-1.11.1p1-8.7", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"cvs-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2003-0015", value:TRUE);
}

set_kb_item(name:"RHSA-2003-013", value:TRUE);
