#
# (C) Tenable Network Security
#


if(description)
{
 script_id(17652);
 script_cve_id("CVE-2005-0962");
 script_bugtraq_id(12944);
 if (defined_func("script_xref")) script_xref(name:"OSVDB", value:"15124");
 script_version("$Revision: 1.7 $");
 name["english"] = "SquirrelCart SQL Injection";
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote web server contains a PHP application that is subject to
SQL injection attacks. 

Description :

The remote host is running SquirrelCart, a shopping cart program
written in PHP. 

There is a flaw in the remote software that may allow anyone to inject
arbitrary SQL commands, which may in turn be used to gain
administrative access on the remote host. 

SquirrelCart 1.5.5 and prior versions are affected by this flaw. 

See also : 

http://www.ldev.com/forums/showthread.php?t=1860

Solution : 

Upgrade to SquirrelCart 1.6.0 or download a patch from
SquirrelCart.com. 

Risk factor : 

Medium / CVSS Base Score : 5 
(AV:R/AC:L/Au:NR/C:P/A:N/I:P/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "SQL Injection in Squirrelcart";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

# Check starts here

include("http_func.inc");
include("http_keepalive.inc");


function check(dir)
{
  local_var req, buf;
  global_var port;

  req = http_get(item:dir + "/store.php?crn=42'&action=show&show_products_mode=cat_click", port:port);
  buf = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if(buf == NULL)exit(0);

  if('SELECT Table_2 FROM REL_SubCats__Cats WHERE Table_2 = ' >< buf )
  	{
	security_warning(port);
	exit(0);
	}
 
 
 return(0);
}

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if ( ! can_host_php(port:port) ) exit(0);


foreach dir (cgi_dirs()) check( dir:dir );
