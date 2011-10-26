# 
# (C) Tenable Network Security
#

if (description)
{
 script_id(19229);
 script_bugtraq_id(14295, 14305, 14306);
 script_version ("$Revision: 1.3 $");

 script_name(english:"VP-ASP SQL Injection (2)");
 desc["english"] = "
The remote host is using the VP-ASP, a shopping cart program written in  ASP.

The remote version of this software is vulnerable to three SQL injection 
vulnerabilities in the files shopaddtocart.asp, shopaddtocartnodb.asp and 
shopproductselect.asp.

An attacker may exploit these flaws to execute arbitrary SQL statements against
the remote database

Solution : See http://www.vpasp.com/virtprog/info/faq_securityfixes.htm
Risk factor : High";

 script_description(english:desc["english"]);
 script_summary(english:"Performs a SQL injection against the remote shopping cart");
 script_category(ACT_ATTACK);
 script_family(english:"CGI abuses", francais:"Abus de CGI");
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

foreach dir ( cgi_dirs() )
{
 req = http_get(item:dir + "/shopaddtocart.asp?productid='42", port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if ( res == NULL ) exit(0);
 
 if("'80040e14'" >< res && "[Microsoft][ODBC SQL Server Driver][SQL Server]" >< res && "'42'" >< res )
 {
  security_hole(port);
  exit(0);
 }
}
