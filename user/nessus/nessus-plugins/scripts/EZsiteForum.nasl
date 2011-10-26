#
# This script  written by deepquest <deepquest@code511.com>
#
# 
#
# Ref: 
#  Date: 4 sep , 2003  7:07:39  AM
#  From: cyber_talon <cyber_talon@hotmail.com>
#  Subject: EZsite Forum Discloses Passwords to Remote Users

if(description)
{
 script_id(11833);
 script_version("$Revision: 1.8 $");
 name["english"] = "EZsite Forum Discloses Passwords to Remote Users";
 script_name(english:name["english"]);
 # script_cve_id("CVE-MAP-NOMATCH");
 # NOTE: reviewed, and no CVE id currently assigned (jfs, december 2003)
 # Also, I've not found a bugtraq ID for this vulnerability
 
 desc["english"] = "
The remote host is running EZsite Forum.

It is reported that this software stores usernames and passwords in
plaintext form in the 'Database/EZsiteForum.mdb' file. A remote user
can reportedly download this database.

Solution : No solution was available at the time. Configure your web server
to disallow the download of .mdb files.

Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for EZsiteForum.mdb password database";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 deepquest");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);


if(!get_port_state(port))exit(0);


sig = get_kb_item("www/hmap/" + port + "/description");
if ( sig && "IIS" >!< sig ) exit(0);

dirs = make_list(cgi_dirs());

foreach d (dirs)
{
 req = http_get(item:string(d, "/forum/Database/EZsiteForum.mdb"), port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 
 if ( res == NULL ) exit(0);
 
 if("Standard Jet DB" >< res)
	{
 	 security_hole(port);
	 exit(0);
	 }
}
