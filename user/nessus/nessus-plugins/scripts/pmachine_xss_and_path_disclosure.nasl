#
# This script is (C) Tenable Network Security
#




if(description)
{
 script_id(11766);
 script_bugtraq_id(7980, 7981);
 script_version ("$Revision: 1.10 $");

 name["english"] = "pmachine cross site scripting";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running a version of pMachine which is vulnerable
to two flaws :
  - It is vulnerable to a path disclosure problem which may allow
    an attacker to gain more knowledge about this host
	  
 - It is vulnerable to a cross-site-scripting attack which may allow
   an attacker to steal the cookies of the legitimates users of
   this service
	  
Solution : None at this time. Disable this CGI suite
Risk factor : Low / Medium";	  




 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of search/index.php";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security",
		francais:"Ce script est Copyright (C) 2003 Tenable Network Security");
 family["english"] = "CGI abuses : XSS";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl", "cross_site_scripting.nasl");
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
if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);
if(!can_host_php(port:port))exit(0);


function check(loc)
{
 req = http_get(item:string(loc, "/search/index.php?weblog=nessus&keywords=<script>foo</script>"),
 		port:port);			
 r = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( r == NULL )exit(0);
 if( "<script>foo</script>" >< r)
 {
 	security_warning(port);
	exit(0);
 }
}



foreach dir (cgi_dirs())
{
 check(loc:dir);
}
