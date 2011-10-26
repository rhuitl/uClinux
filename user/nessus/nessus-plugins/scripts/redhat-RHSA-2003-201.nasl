#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12404);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2003-0251");

 name["english"] = "RHSA-2003-201: ypserv";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated ypserv packages fixing a denial of service vulnerability are now
  available.

  The ypserv package contains the Network Information Service (NIS) server.

  A vulnerability has been discovered in the ypserv NIS server prior to
  version 2.7. If a malicious client queries ypserv via TCP and subsequently
  ignores the server\'s response, ypserv will block attempting to send the
  reply. This results in ypserv failing to respond to other client requests.

  Versions 2.7 and above of ypserv have been altered to fork a child for each
  client request, thus preventing any one request from causing the server to
  block.

  Red Hat recommends that users of NIS upgrade to these packages, which
  contain version 2.8.0 of ypserv and are therefore not vulnerable to this
  issue.




Solution : http://rhn.redhat.com/errata/RHSA-2003-201.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the ypserv packages";
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
if ( rpm_check( reference:"ypserv-2.8-0.AS21E", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"ypserv-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2003-0251", value:TRUE);
}

set_kb_item(name:"RHSA-2003-201", value:TRUE);
