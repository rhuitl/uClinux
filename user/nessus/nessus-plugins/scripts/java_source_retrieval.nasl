#
# (C) Tenable Network Security

if (description)
{
 script_id(12245);
 script_version ("$Revision: 1.3 $");
 
 script_name(english:"Jave Source Code Disclosure");
 desc["english"] = "
The remote host potentially discloses java source code.
That is, this script attempts to download .java and .class
files of known java applets.

Risk factor : Medium";

 script_description(english:desc["english"]);
 script_summary(english:"Jave Source Code Disclosure check");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses", francais:"Abus de CGI");
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 script_dependencie("find_service.nes", "webmirror.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}


# start script


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(! get_port_state(port))
	exit(0);


init = get_kb_list(string("www/", port, "/java_classfile"));

if (isnull(init)) 
	exit(0);


master = make_list(init);
mylist = make_list();



# Ensure that web server doesn't respond with '200 OK' for everything
req = http_get(item:string("Nessus", rand() % 65535, ".class"), port:port);
soc = http_open_socket(port);
if (!soc) 
	exit(0);

send (socket:soc, data:req);
res = recv_line(socket:soc, length:512);
http_close_socket(soc);

if (! res || ("200 OK" >< res) ) 
	exit(0);


vcounter = 0;

foreach script (master) 
{
    if ( (".class" >< tolower(script)) || (".java" >< tolower(script)) ) 
    {
        rootname = ereg_replace(string:script, pattern:"\.class|\.java", replace:"", icase:TRUE);
    } 
    else 
    {
        rootname = script;
    }

    req  = http_get(item:string(rootname, ".class"), port:port);
    req2 = http_get(item:string(rootname, ".java"),  port:port);

    if ("http://" >!< req)  
    {
	res  = http_keepalive_send_recv(port:port, data:req);
        if (res == NULL) 
		exit(0);
    }

    if ("http://" >!< req2) 
    {
	res2 = http_keepalive_send_recv(port:port, data:req2);
        if (res == NULL)
		exit(0);
    }

    if (egrep(string:res, pattern:"^HTTP/.* 200 OK"))
    {
	mylist = make_list(mylist, string(rootname, ".class")); 
	vcounter++;
    }

    if (egrep(string:res2, pattern:"^HTTP/.* 200 OK"))
    {
	mylist = make_list(mylist, string(rootname, ".java") ); 
	vcounter++;
    }

    if (vcounter > 20) 
	break;        

    res = res2 = req = req2 = rootname = NULL;
}







if (vcounter) 
{
    mywarning = string("The remote host appears to allow downloads of java source or class files.
An attacker can decompile class files using a tool such as 'jad'.  Source
files or decompiled class files can often contain interesting information
regarding network configurations, userIDs, gateways, passwords, etc.  You
will surely wish to evaluate each of these java files individually.

Reference: http://kpdus.tripod.com/jad.html

Specifically, the following files could be downloaded:\n\n");

    foreach z (mylist) 
    {
        mywarning += string(z,"\n");
    }

    security_note(port:port, data:mywarning);
}




