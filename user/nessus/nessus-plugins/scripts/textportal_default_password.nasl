#
# (C) Tenable Network Security
#
# See the Nessus Scripts License for details
#
# Ref:
#
# From: "bugtracklist.fm" <bugtracklist@freemail.hu>
# To: <bugtraq@securityfocus.com>
# Subject: TextPortal Default Password Vulnerability
# Date: Sat, 24 May 2003 00:15:52 +0200


if(description)
{
 script_id(11660);
 script_bugtraq_id(7673);
 script_version("$Revision: 1.7 $");
 
 name["english"] = "TextPortal Default Passwords";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running the TextPortal content management interface.
This set of scripts come with two default administrator passwords :
	- admin
	- 12345
	
At least one of these two passwords is still set. An attacker
could use them to edit the content of the remote website.

Solution : edit admin_pass.php and change the passwords of these users
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Logs into the remote TextPortal interface";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

# Check starts here

include("http_func.inc");
include("http_keepalive.inc");

function check(dir, passwd)
{
 req = http_post(item:dir + "/admin.php", port: port, data:"op=admin_enter&passw=" + passwd);
 idx = stridx(req, 'Content-Length');
 req = insstr(req, '\r\nContent-Type: application/x-www-form-urlencoded', idx - 2, idx - 2);
 res = http_keepalive_send_recv(port:port, data:req);
 if (res == NULL ) exit(0);
 if ("admin.php?blokk=" >< res) return(1);
}

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

passwds = make_list("admin", "12345");

if(get_port_state(port))
{
 foreach dir (cgi_dirs())
 {
 	if(is_cgi_installed_ka(port:port, item:dir + "/admin.php"))
	{
 		foreach pass (passwds)
		{
 			if(check(dir:dir, passwd:pass))
 			{
 			security_hole(port);
			exit(0);
 			}
 		}	
	}
 }
}
