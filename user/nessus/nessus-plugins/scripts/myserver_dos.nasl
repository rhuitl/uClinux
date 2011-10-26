#
# (C) Tenable Network Security
#

if(description)
{
 script_id(11770);
 script_bugtraq_id(6359, 7770, 7917, 8010, 8120);
 script_version ("$Revision: 1.7 $");

 
 name["english"] = "myServer DoS";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running myServer 0.4.2 or older.

There are flaws in this software which may allow an attacker
to disable this service remotely.

Solution : Upgrade to the latest version or use another web server
Risk factor : Medium";



 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of myServer";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 
 family["english"] = "Denial of Service";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}




include("http_func.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

banner = get_http_banner(port:port);
if(!banner) exit(0);
if(egrep(pattern:"^Server:MyServer 0\.([0-3]\.|4\.[0-2])[^0-9]", string:banner))
	{
	  security_warning(port);
	}


