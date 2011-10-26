#
# (C) Tenable Network Security
#

if(description)
{
 script_id(12110);
 script_bugtraq_id(9899);
 script_version("$Revision: 1.14 $");
 script_cve_id("CVE-2004-0079", "CVE-2004-0081", "CVE-2004-0112");
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2004-B-0006");
 name["english"] = "OpenSSL denial of service";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is using a version of OpenSSL which is
older than 0.9.6m or 0.9.7d

There are several bug in this version of OpenSSL which may allow
an attacker to cause a denial of service against the remote host.

*** Nessus solely relied on the banner of the remote host
*** to issue this warning

Solution : Upgrade to version 0.9.6m (0.9.7d) or newer
Risk factor : High";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks for version of OpenSSL";
 summary["francais"] = "Verifie la version de OpenSSL";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Denial of Service";
 script_family(english:family["english"]);
 if ( ! defined_func("bn_random") )
 	script_dependencie("http_version.nasl");
 else
 	script_dependencie("find_service.nes", "http_version.nasl", "macosx_SecUpd20040503.nasl", "redhat-RHSA-2004-119.nasl", "redhat-RHSA-2004-120.nasl");
 script_require_ports("Services/www", 443);
 exit(0);
}

#
# The script code starts here - we rely on Apache to spit OpenSSL's
# version. That sucks.
#

include("http_func.inc");
include("misc_func.inc");
include("backport.inc");


if ( get_kb_item("CVE-2004-0079") ) exit(0);
if ( get_kb_item("CVE-2004-0081") ) exit(0);

#
# Only look at the banner for now. This test needs to be improved.
# 
ports = add_port_in_list(list:get_kb_list("Services/www"), port:443);

foreach port (ports)
{
 banner = get_http_banner(port:port);
 if(banner)
  {
  banner = get_backport_banner(banner:banner);
  if(egrep(pattern:"^Server:.*OpenSSL/0\.9\.([0-5][^0-9]|6[^a-z]|6[a-l]).*", string:banner)) security_hole(port);
  else if(egrep(pattern:"^Server:.*OpenSSL/0\.9\.7(-beta.*|[a-c]| .*)", string:banner)) security_hole(port);
  }
}
