#
# This script was written by H D Moore
# 
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID and CVE


if(description)
{
    script_id(10996);
    script_bugtraq_id(1386);
    script_version ("$Revision: 1.11 $");
    script_cve_id("CVE-2000-0539");
    name["english"] = "JRun Sample Files";
    name["francais"] = "JRun Sample Files";
    script_name(english:name["english"], francais:name["francais"]);


    desc["english"] = "
This host is running the Allaire JRun web server 
and has sample files installed.  Several of the 
sample files that come with JRun contain serious 
security flaws.  An attacker can use these 
scripts to relay web requests from this machine 
to another one or view sensitive configuration 
information. 
    

Solution: Sample files should never be left on production 
          servers.  Remove the sample files and any other 
          files that are not required.
          
Risk factor : High 
";

    desc["francais"] = "JRun Sample Files";

    script_description(english:desc["english"], francais:desc["francais"]);


    summary["english"] = "Checks for the presence of JRun sample files";
    summary["francais"] = "Vérifie la présence de JRun sample files";
    script_summary(english:summary["english"], francais:summary["francais"]);


    script_category(ACT_GATHER_INFO);

    script_copyright(english:"This script is Copyright (C) 2001 Digital Defense Inc.",
               francais:"Ce script est Copyright (C) 2001 Digital Defense Inc.");

    family["english"] = "Backdoors";
    family["francais"] = "Backdoors";
    script_family(english:family["english"], francais:family["francais"]);
    script_dependencie("http_version.nasl");
    script_require_ports("Services/www", 80);
    
    exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

#
# The script code starts here
#


file[0] = "/cfanywhere/index.html";     res[0] = "CFML Sample";
file[1] = "/docs/servlets/index.html";  res[1] = "JRun Servlet Engine";
file[2] = "/jsp/index.html";            res[2] = "JRun Scripting Examples";
file[3] = "/webl/index.html";           res[3] = "What is WebL";

port = get_http_port(default:80);



if(!get_port_state(port)){ exit(0); }

function check_page(req, pat)
{
    str = http_get(item:req, port:port);
    r = http_keepalive_send_recv(data:str, port:port);
    if( r == NULL ) exit(0);
    if(pat >< r)
            {
                security_hole(port:port);
                exit(0);
            }
    return(0);
}

for(i=0;file[i];i=i+1)
{
    req = file[i];
    pat = res[i];
    check_page(req:req, pat:pat);
}
