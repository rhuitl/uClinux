#
#  (C) Tenable Network Security
#
#

if(description)
{
 script_id(11689);
 script_version ("$Revision: 1.6 $");
 
 name["english"] = "Cisco IDS Device Manager Detection";
 script_name(english:name["english"]);
 
 desc["english"] = "This host is running the Cisco IDS device manager.";

 script_description(english:desc["english"]);
 
 summary["english"] = "Cisco IDS Management Web Server Detect";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 family["english"] = "General";
 script_family(english:family["english"]);

 script_copyright(english:"This script is Copyright (C) Tenable Network Security");
 script_dependencie("httpver.nasl");
 script_require_ports("Services/www", 443);
 exit(0);
}

#
# The script code starts here
#
 include("http_func.inc");
 include("http_keepalive.inc");

 port = get_http_port(default:443);
 if (!port) exit(0);

 file = http_get_cache(port:port, item:"/");
 if ( ! file )exit(0);

 if("<title>Cisco Systems IDS Device Manager</title>" >< file )
	{
   	security_note(port);
	set_kb_item(name:"Services/www/" + port + "/embedded", value:TRUE);
	}
