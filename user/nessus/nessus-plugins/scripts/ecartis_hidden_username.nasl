#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#



if(description)
{
 script_id(11505);
 script_bugtraq_id(6971);
 script_cve_id("CVE-2003-0162");
 
 script_version ("$Revision: 1.6 $");


 name["english"] = "Ecartis Username Spoofing";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running the Ecartis Mailing List Manager
web interface (lsg2.cgi).

There is a vulnerability in versions older than 1.0.0 snapshot 20030227
which allows an attacker to spoof a username while changing passwords,
thus gaining the control of the mailing list.

*** Nessus solely relied on the version number of this CGI,
*** so this might be a false positive.


Solution : Upgrade to version 1.0.0 snapshot 20030227
Risk factor : Medium";




 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of lsg2.cgi";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2003 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);






foreach dir (make_list("/ecartis", cgi_dirs()))
{
 req = http_get(item:string(dir, "/lsg2.cgi"), port:port);
 res = http_keepalive_send_recv(port:port, data:req);

 if( res == NULL ) exit(0);

 if(egrep(pattern:"Ecartis (0\..*|1\.0\.0)", string:res))
 	{
	security_warning(port);
	exit(0);
	}
}
