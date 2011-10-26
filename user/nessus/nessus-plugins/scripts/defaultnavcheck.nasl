# Copyright (C) 2000 - 2004 Net-Square Solutions Pvt Ltd.
# By: Hemil Shah
# Desc: This script will check for the DefaultNav vuln working on remote web server.
if(description)
{
	script_id(12247);

	script_version ("$Revision: 1.3 $");

 	name["english"] = "DefaultNav checker";
 	script_name(english:name["english"]);

	desc["english"] = 
"This plugin checks for DefaultNav vulnerabilities on the remote web server

For more information, see:
http://www.nextgenss.com/advisories/defaultnav.txt

Risk : High";

	script_description(english:desc["english"]);

 	summary["english"] = "DefaultNav checker";
	script_summary(english:summary["english"]);

	script_category(ACT_ATTACK);

	script_copyright(english:"This script is Copyright (C) 2004 Net-Square Solutions Pvt Ltd.");
	family["english"] = "Misc.";
	script_family(english:family["english"]);

	script_dependencie("find_service.nes");
	script_require_ports("Services/www", 80);
	exit(0);
}

# start script
include("http_func.inc");
include("http_keepalive.inc");


exit(0); # Broken

port = get_http_port(default:80);

if(! get_port_state(port))
    exit(0);

if ( get_kb_item("www/no404/" + port ) ) exit(0);

DEBUG = 0;


dirs[0] = "/%24DefaultNav";
dirs[1] = "/%24defaultNav";
dirs[2] = "/%24%64*efaultNav";
dirs[3] = "/%24%44*efaultnav";
dirs[4] = "/$defaultNav";
dirs[5] = "/$DefaultNav";
dirs[6] = "/$%64efaultNav";
dirs[7] = "/$%44efaultNav";

report = string("The DefaultNav request is enabled on the remote host\n");



nsfName = "/names.nsf";

for (i=0; dirs[i]; i++)
{   
	res = http_keepalive_send_recv(port:port, data:http_get(item:string(nsfName, dirs[i], "/"), port:port));

	if ( res == NULL ) exit(0);
       
        if(ereg(pattern:"HTTP/1.[01] 200", string:res) && res!=customres)
        {
	    report = report + string("specifically, the request for ", nsfName, dirs[i], "/ is\n");
            report = report + string("capable of remotely compromising the integrity of the\n");
	    report = report + string("system.  For more information, please see:\n");
	    report = report + string("http://www.nextgenss.com/advisories/defaultnav.txt\n");
            security_hole(port:port, data:report);            
            exit(0);
        }
}


