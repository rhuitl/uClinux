#
# (C) Tenable Network Security
#

if(description)
{
 script_id(15927);
 script_bugtraq_id(11802);
 script_version ("$Revision: 1.6 $");
 name["english"] = "HFS+ 'data fork' file access";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host seems to be running MacOS X or MacOS X Server.

There is a flaw in the remote web server which allows an attacker
to obtain the source code of any given file on the remote web
server by reading it through its data fork directly. An attacker
may exploit this flaw to obtain the source code of remote scripts.

Solution :  install all the latest Apple Security Patches
Risk factor : High";
	
 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "downloads the source of a remote script";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if ( ! port ) exit(0);

if ( get_kb_item("www/no404/" + port  ) ) exit(0);

function check(file, pattern)
{
  req = http_get(item:string(file, "/..namedfork/data"), port:port);
  r = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
  if ( ! r ) exit(0);
  if ( ereg(pattern:"^HTTP/.* 200 ", string:r) && (pattern >< r ))
	{
	security_hole ( port );
	return 1;
	}

 return 0 ;
}

port = get_http_port(default:80);

if(get_port_state(port))
{
 check(file:"/index.php", pattern:"<?");
 files = get_kb_list(string("www/", port, "/content/extensions/php"));
 if(!isnull(files))
 {
 files = make_list(files);
 check(file:files[0], pattern:"<?");
 }
 res = http_keepalive_send_recv(port:port, data:http_get(item:"/index.html", port:port), bodyonly:1);
 if ( ! res ) exit(0);
 check(file:"/index.html", pattern:res);
}


