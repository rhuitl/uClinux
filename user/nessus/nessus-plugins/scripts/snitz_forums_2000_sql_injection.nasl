#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from
#  (C) Tenable Netwok Security
#
# This script is released under the GNU GPLv2

if (description)
{
script_id(14227);
script_bugtraq_id(7549);
 script_cve_id("CVE-2003-0286");
 if ( defined_func("script_xref") ) script_xref(name:"OSVDB", value:"4638");


 script_name(english:"Snitz Forums 2000 SQL injection");
 script_version ("$Revision: 1.8 $");
 desc["english"] = "
The remote host is using Snitz Forum 2000

This version allow an attacker to execute stored procedures 
and non-interactive operating system commands on the system. 

The problem stems from the fact that the 'Email' variable
in the register.asp module fails to properly validate and
strip out malicious SQL data.  

An attacker, exploiting this flaw, would need network access
to the webserver.  A successful attack would allow the 
remote attacker the ability to potentially execute arbitrary
system commands through common SQL stored procedures such 
as xp_cmdshell.

Solution: Upgrade to version 3.4.03 or higher

Risk factor : High";

 script_description(english:desc["english"]);
 script_summary(english:"Determine Snitz forums version");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses", francais:"Abus de CGI");
 
 script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
 
 script_dependencie("find_service.nes", "no404.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if ( ! can_host_asp(port:port) ) 
	exit(0);

if(!get_port_state(port))
	exit(0);

url = "/forum/register.asp";
req = http_get(item:url, port:port);
buf = http_keepalive_send_recv(port:port, data:req);
if( buf == NULL ) 
	exit(0);

# Ex: Powered By: Snitz Forums 2000 Version 3.4.03

#if("Powered By: Snitz Forums 2000 3.3.03" >< buf )
# jwl: per CVE, all version prior to 3.3.03 are vulnerable
if (egrep(string:buf, pattern:"Powered By: Snitz Forums 2000 ([0-2]\.*|3\.[0-2]\.*|3\.3\.0[0-2])"))
{
	security_hole(port);
    	exit(0);
}


