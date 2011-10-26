#
# Copyright (C) 2004 Tenable Network Security
#
if(description)
{
 script_id(12251);
 script_version ("$Revision: 1.1 $");

 name["english"] = "RealServer default.cfg file search";

 script_name(english:name["english"]);

 desc["english"] = "
The remote RealServer seems to allow any anonymous user
to download the default.cfg file.  This file is used to
store confidential data and should not be accessible via
the web frontend.

Risk factor : High

Solution : Remove or protect the named resource";

 script_description(english:desc["english"]);

 summary["english"] = "RealServer default.cfg file search";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);


 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security",
                francais:"Ce script est Copyright (C) 2004 Tenable Network Security");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes");
 script_require_ports("Services/realserver", 7070);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");


port = get_kb_item("Services/realserver");
if (!port) 
	port = 7070;

if (! get_tcp_port_state(port) )
	exit(0);

req = http_get(item:string("/admin/Docs/default.cfg") , port:port);

r = http_keepalive_send_recv(port:port, data:req);

if( r == NULL )
	exit(0);

if(egrep(pattern:".*Please read the configuration section of the manual.*", string:r)) 
    security_warning(port);



