#
# (C) Tenable Network Security
#
# 

if(description)
{
 script_id(12094);
 script_cve_id("CVE-2004-2278");
 script_bugtraq_id(9860);
 if (defined_func("script_xref")) {
   script_xref(name:"OSVDB", value:"4207");
 }
 
 script_version("$Revision: 1.8 $");
 name["english"] = "vHost Cross-Site scripting vulnerabilities";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running a version of vHost which is older than 3.10r1.

There is a cross site scripting vulnerability in this version which may
allow an attacker to steal the cookies of the legitimate users of this site.

Solution : Upgrade to the vHost 3.10r1 or later.
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "version test for vHost";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "CGI abuses : XSS";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

# Check starts here

include("http_func.inc");
include("http_keepalive.inc");

function check(dir)
{
  if ( defined_func("unixtime") ) time = unixtime();
  else time = "1021231234";
  req = http_get(item:dir + "/vhost.php?action=logout&time=" + time, port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if ( res == NULL ) exit(0);

  if ("<!-- vhost" >< res )
   {
    if ( egrep(pattern:"<!-- vhost ([12]\.|3\.([0-9][^0-9]|10[^r]))", string:res) ) {
	security_warning(port);
	exit(0);
    }
   }
 return(0);
}

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);


foreach dir ( cgi_dirs() )
{
 check(dir:dir);
}
