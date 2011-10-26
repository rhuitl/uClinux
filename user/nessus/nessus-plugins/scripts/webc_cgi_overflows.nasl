#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
# Ref:
# From: Carl Livitt <carl@learningshophull.co.uk>   
# To: bugtraq@securityfocus.com
# Subject: Multiple vulnerabilities in AutomatedShops WebC shopping cart
# Date: Thu, 3 Apr 2003 14:22:36 +0100


if(description)
{
 script_id(11516);
 script_bugtraq_id(7268);
 script_version ("$Revision: 1.3 $");



 name["english"] = "AutomatedShops WebC.cgi buffer overflows";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running a version of AutomatedShops's webc.cgi
which is older than version 5.020.

This CGI is vulnerable to a remote buffer overflow (up to version 5.005 included)
and to a local one (up to version 5.010 included)

An attacker may use this flaw to execute arbitrary code on the remote
host.

Solution : Upgrade to version 5.020
Risk factor : High";





 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of webc.cgi";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2003 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("webc_cgi_installed.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);


version = get_kb_item(string("www/", port, "/content/webc.cgi/version"));
if(version)
{
 if(ereg(pattern:"([0-4]\..*|5\.0([0-1][0-9])) ", string:version))
 	security_hole(port);
}

