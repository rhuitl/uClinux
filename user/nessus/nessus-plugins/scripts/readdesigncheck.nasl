# Copyright (C) 2000 - 2004 Net-Square Solutions Pvt Ltd.
# By: Hemil Shah
# Desc: This script will check for the ReadDesign vuln on names.nsf.
if(description)
{
	script_id(12249);
	script_version ("$Revision: 1.5 $");
 	name["english"] = "ReadDesign checker";
 	script_name(english:name["english"]);
	desc["english"] = 
"This plugin checks for ReadDesign vulns on the remote web server.

For more information, see:

https://www.appsecinc.com/Policy/PolicyCheck1520.html

Risk: Medium";
	script_description(english:desc["english"]);
 	summary["english"] = "ReadDesign checker";
	script_summary(english:summary["english"]);
	script_category(ACT_GATHER_INFO);
	script_copyright(english:"This script is Copyright (C) 2004 Net-Square Solutions Pvt Ltd.");
	family["english"] = "Misc.";
	script_family(english:family["english"]);
	script_dependencie("webmirror.nasl", "http_version.nasl");
	script_require_ports("Services/www", 80);
	exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

port = get_http_port(default:80);

if(! get_port_state(port)) exit(0);

if ( get_kb_item("www/no404/" + port) ) exit(0);


nsf =  get_kb_list(string("www/", port, "/content/extensions/nsf"));
if ( ! isnull(nsf) ) {
	nsf = make_list(nsf);
	file = nsf[0];
	}
else
	file = "/names.nsf";




report = string("The ReadDesign vulnerability was found on the server.
Specifically, configuration information may be leaked which would aid
an attacker in future exploits\n");



req = string(file, "/view?ReadDesign");
http = http_get(item:req, port:port);
res = http_keepalive_send_recv(port:port, data:http, fetch404:TRUE);
if ( res == NULL ) exit(0);

       
if( egrep(pattern:"HTTP Web Server: .* - view", string:res) )
        {	
	    report = report + string("The following request triggered the vulnerability\n");
	    report = report + string(req, "\nRisk: Low\n"); 
            report = report + string("Solution :\nCf https://www.appsecinc.com/Policy/PolicyCheck1520.html");
            security_note(port:port, data:report);            
            exit(0);
        }

