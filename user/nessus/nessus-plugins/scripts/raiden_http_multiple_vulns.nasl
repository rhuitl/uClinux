#
# (C) Tenable Network Security
#

if(description)
{
 script_id(17243);
 script_bugtraq_id(12688);
 script_version ("$Revision: 1.1 $");
 
 name["english"] = "RaidenHTTPD Multiple Remote Vulnerabilities";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The remote host is running RaidenHTTPD 1.1.33 or older. 

Ther are various flaws in the remote version of this server which may
allow an attacker to disclose the source code of any PHP file hosted
on the remote server, or to execute arbitrary code on the remote with
the privileges of the remote server (usually SYSTEM).

Solution : Upgrade to RaidenHTTPD 1.1.34 or newer
Risk Factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "RaidenHTTPD check";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Gain root remotely";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");

port = get_http_port(default:80);
if ( ! port ) exit(0);
banner = get_http_banner(port: port);
if ( ! banner ) exit(0);

if ( egrep(pattern:"Server: RaidenHTTPD/(0\.|1\.0|1\.1\.[0-9] |1\.1\.[0-2][0-9] |1\.1\.3[0-3] )", string:banner) ) security_hole ( port );
