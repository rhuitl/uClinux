#
# This script is (C) Tenable Network Security
#
# ref: http://www.kernelpanik.org/docs/kernelpanik/wordpressadv.txt
#




if(description)
{
 script_id(11703);
 script_bugtraq_id(7785);
 script_version ("$Revision: 1.8 $");

 name["english"] = "WordPress code/sql injection";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis : 

The remote web server contains PHP scripts that allow for arbitrary PHP
code execution and local file disclosure as well as SQL injection
attacks. 

Description :

It is possible to make the remote host include php files hosted on a
third-party server using the WordPress CGI suite which is installed
(which is also vulnerable to a SQL injection attack). 

An attacker may use this flaw to inject arbitrary PHP code in the remote
host and gain a shell with the privileges of the web server or to take
the control of the remote database. 

See also : 

http://www.kernelpanik.org/docs/kernelpanik/wordpressadv.txt

Solution : 

Upgrade to the latest version.

Risk factor : 

High / CVSS Base Score : 7 
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of WordPress";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2003-2005 Tenable Network Security",
		francais:"Ce script est Copyright (C) 2003-2005 Tenable Network Security");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("wordpress_detect.nasl");
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
if(!can_host_php(port:port))exit(0);



function check_php_inc(loc)
{
 req = http_get(item:string(loc, "/wp-links/links.all.php?abspath=http://xxxxxxxx"),
 		port:port);			
 r = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
 if( r == NULL )exit(0);
 if("http://xxxxxxxx/blog.header.php" >< r)
 {
 	security_hole(port);
	exit(0);
 }
}

function check_sql_inj(loc)
{
 req = http_get(item:string(loc, "/index.php?posts='"),
 		port:port);			
 r = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
 if( r == NULL )exit(0);
 if("mysql_fetch_object()" >< res)
 {
 	security_hole(port);
	exit(0);
 }
}




# Test an install.
install = get_kb_item(string("www/", port, "/wordpress"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
 loc = matches[2];

 check_php_inc(loc:loc);
 check_sql_inj(loc:loc);
}
