# 
# (C) Tenable Network Security
#
# SEE:http://www.securityfocus.com/archive/1/323224
#

if(description)
{
 script_id(11682);
 script_version ("$Revision: 1.6 $");
 
 name["english"] = "Philboard database access";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running Philboard. It is possible to download
the database of this server (philboard.mdb) and to obtain
valuable information from it (passwords, archives, and so on).

Solution : Prevent the download of .mdb files from your web server. 
Risk factor : High";
 script_description(english:desc["english"]);
 
 summary["english"] = "Downloads philboard.mdb";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security",
francais:"Ce script est Copyright (C) 2003 Tenable Network Security");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

# The script code starts here
include("http_func.inc");
include("http_keepalive.inc");

function check(loc)
{
 req = http_get(item:loc, port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if( res == NULL ) exit(0);
 if("Standard Jet DB" >< res) { security_hole(port); exit(0); }
}

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);


dirs = make_list("/forum", cgi_dirs());

foreach dir (dirs)
{
 check(loc: dir + "/database/philboard.mdb");		
}
