#
# (C) Tenable Network Security
#
# Ref : http://dev2dev.bea.com/resourcelibrary/advisoriesnotifications/BEA03-30.jsp
#
#

if(description)
{
 script_id(11628);
 script_version ("$Revision: 1.3 $");
 
 
 name["english"] = "WebLogic Certificates Spoofing";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote web server is running WebLogic.

There is a bug in this version which may allow an attacker to perform
a man-in-the-middle attack against the remote server by supplying a 
self-signed certificate. 

An attacker with a legitimate certificate may use this flaw to impersonate
any other user on the remote server.

Solutions : http://dev2dev.bea.com/resourcelibrary/advisoriesnotifications/BEA03-31.jsp
Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks the version of WebLogic";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 family["english"] = "Misc.";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/weblogic");
 exit(0);
}

#

include("http_func.inc");

port = get_http_port(default:80);

if (! get_port_state(port)) exit(0);

banner = get_http_banner(port:port);

if ("CR090101" >< banner) exit(0);

if(banner =~ "WebLogic .* 5\.")
{
 security_warning(port);
 exit(0);
}

if (banner =~ "WebLogic .* 6\.1 ")
{
  if (banner !~ " SP[5-9]") security_warning(port);
  exit(0);
}

if (banner =~ "WebLogic .* 6\.0 ")
{
  security_warning(port); # Should upgrade to 6.1
  exit(0);
}

if (banner =~ "WebLogic .* 7\.0(\.0\.1)? ")
{
  if (banner !~ " SP[2-9]") security_warning(port);
  exit(0);
}
