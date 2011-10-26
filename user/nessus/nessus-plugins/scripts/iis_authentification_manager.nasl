#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
# 2002-06-07 [Michel Arboi]
# I added aexp3.htr and the comment about the locked account.
#

if(description)
{
 script_id(10371);
 script_bugtraq_id(2110, 4236);
 script_version ("$Revision: 1.23 $");
 script_cve_id("CVE-1999-0407", "CVE-2002-0421");

 name["english"] = "/iisadmpwd/aexp2.htr";
 script_name(english:name["english"]);
 
 desc["english"] = "
The file /iisadmpwd/aexp2.htr is present.
(or, aexp2b.htr, aexp3.htr, or aexp4.htr, search for aexp*.htr)

An attacker may use it in a brute force attack
to gain valid username/password.
A valid user may also use it to change his password
on a locked account.

Solution : Delete the file
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Determines whether /iisadmpwd/aexp2.htr is present";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison");
 family["english"] = "Web Servers";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl", "www_fingerprinting_hmap.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");

function test_cgi(port, cgi, output)
{
 req = http_get(item:cgi, port:port);
 r = http_keepalive_send_recv(port:port, data:req);
 if(output >< r)
  {
  	security_hole(port);
	exit(0);
  }
 return(0);
}
 
 


port = get_http_port(default:80);

sig = get_kb_item("www/hmap/" + port + "/description");
if ( sig && "IIS" >!< sig ) exit(0);
if(get_port_state(port))
{
  test_cgi(port:port, 
 	  cgi:"/iisadmpwd/aexp.htr",
	  output:"IIS - Authentication Manager");	  

  test_cgi(port:port, 
 	  cgi:"/iisadmpwd/aexp2.htr",
	  output:"IIS - Authentication Manager");	  
  test_cgi(port:port,
          cgi:"/iisadmpwd/aexp2b.htr",
          output:"IIS - Authentication Manager"); 
  test_cgi(port:port,
          cgi:"/iisadmpwd/aexp3.htr",
          output:"IIS - Authentication Manager");      
  test_cgi(port:port,
          cgi:"/iisadmpwd/aexp4.htr",
          output:"IIS - Authentication Manager");      

  test_cgi(port:port,
          cgi:"/iisadmpwd/aexp4b.htr",
          output:"IIS - Authentication Manager");      
}
	  
