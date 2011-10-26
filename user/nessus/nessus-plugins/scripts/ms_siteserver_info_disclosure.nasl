# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID


if (description)
{
 script_id(11018);
 script_cve_id("CVE-2002-1769");
 script_bugtraq_id(3998);
 script_version("$Revision: 1.14 $");
 script_name(english:"MS Site Server Information Leak");
 desc["english"] = "
The remote web server seems to leak information when some
pages are accessed using the account 'LDAP_AnonymousUser' with
the password 'LdapPassword_1'.

Pages which leak information include, but are not limited to :
/SiteServer/Admin/knowledge/persmbr/vs.asp
/SiteServer/Admin/knowledge/persmbr/VsTmPr.asp
/SiteServer/Admin/knowledge/persmbr/VsLsLpRd.asp
/SiteServer/Admin/knowledge/persmbr/VsPrAuoEd.asp

An attacker may use this flaw to modify data on this host

Solution : Install SP4 for Site Server 3.0
Risk factor : High";


 script_description(english:desc["english"]);
 script_summary(english:"Determine if the remote host is vulnerable to a disclosure vuln.");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");
 script_copyright(english:"(c) 2002 Renaud Deraison");
 script_dependencie("find_service.nes", "http_version.nasl", "www_fingerprinting_hmap.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");


function make_request(port, file)
{
 
  req = string("GET ", file, " HTTP/1.1\r\n",
  		"Host: ", get_host_name(), "\r\n",
		"Authorization: Basic bmVzc3VzOm5lc3N1cw==\r\n\r\n");
  
  r = http_keepalive_send_recv(port:port, data:req);
  if( r == NULL ) exit(0);
  
  if (ereg(pattern:"^HTTP/[0-9]\.[0-9] 200 ", string:r))
    exit(0);

  req = string("GET ", file, " HTTP/1.1\r\n",
  		"Host: ", get_host_name(), "\r\n",
		"Authorization: Basic TERBUF9Bbm9ueW1vdXM6TGRhcFBhc3N3b3JkXzE=\r\n\r\n");
  
  r = http_keepalive_send_recv(port:port, data:req);
  if( r == NULL ) exit(0);
  
  if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 200 ", string:r))
  {
    if(get_kb_item(string("www/no404/", port)))
     {
     if("Microsoft" >< r){
      	security_hole(port);
	exit(0);
     }
    }
    else {
      	security_hole(port);
	exit(0);
    }
  }
}
port = get_http_port(default:80);




if ( get_kb_item("www/no404/" + port) ) exit(0);

if( can_host_asp(port:port) )
{
 make_request(port:port, file:"/SiteServer/Admin/knowledge/persmbr/vs.asp"); 
 make_request(port:port, file:"/SiteServer/Admin/knowledge/persmbr/VsTmPr.asp"); 
 make_request(port:port, file:"/SiteServer/Admin/knowledge/persmbr/VsLsLpRd.asp"); 
 make_request(port:port, file:"/SiteServer/Admin/knowledge/persmbr/VsPrAuoEd.asp"); 
}
