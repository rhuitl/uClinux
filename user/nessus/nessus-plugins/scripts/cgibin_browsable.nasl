#
# Copyright 2000 by Hendrik Scholz <hendrik@scholz.net>
#

if(description)
{
 script_id(10039);
 script_version ("$Revision: 1.21 $");
 name["english"] = "/cgi-bin directory browsable ?";
 script_name(english:name["english"]);
 
 desc["english"] = "
The /cgi-bin directory is browsable.
This will show you the name of the installed common scripts 
and those which are written by the webmaster and thus may be 
exploitable.

Solution : Make the /cgi-bin non-browsable. 

Risk factor : Medium";


 script_description(english:desc["english"]);
 
 summary["english"] = "Is /cgi-bin browsable ?";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Hendrik Scholz");

 family["english"] = "CGI abuses";
 script_family(english:family["english"]);

 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here

include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);

if(!get_port_state(port))exit(0);


dirs = NULL;
report_head = "
The following CGI directories are browsable :
";

report_tail = "


This shows an attacker the name of the installed common scripts and those 
which are written by the webmaster and thus may be exploitable.

Solution : Make these directories non-browsable. 

Risk factor : Medium";

foreach dir (cgi_dirs())
{
 if ( strlen(dir) )
 {
 data = string(dir ,"/");
 req = http_get(item:data, port:port);
 buf = http_keepalive_send_recv(port:port, data:req);
 if( buf == NULL ) exit(0);
 if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 200 ", string:buf))
 {
  buf = tolower(buf);
  if(dir == "") must_see = "index of";
  else must_see = string("<title>", dir);
  if( must_see >< buf ){
  	dirs += '.  ' + dir + '\n';
	}
 }
 }
}

if (dirs != NULL )
{
 security_warning(port:port, data:report_head + dirs + report_tail);
}


