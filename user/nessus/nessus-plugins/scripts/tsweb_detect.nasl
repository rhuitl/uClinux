#
# (C) Tenable Network Security
#

 desc["english"] = "
Synopsis :

Terminal Services Client ActiveX is available.

Description :

The remote host appears to be configured to facilitate the client
download of an ActiveX Terminal Services Client.  So, users can access the
web page and click a 'connect' button which will prompt a client-side download
of a .cab file which will be used to connect the client directly to a
terminal services server using Remote Desktop Protocol -- RDP.  Of course,
you will want to manually inspect this page for possible information regarding
systems offering RDP access, system information, IP addressing information, etc.

Solution :

password protect access to the 'tsweb' resource.

Risk factor :

None / CVSS Base Score : 0 
(AV:R/AC:L/Au:NR/C:N/A:N/I:N/B:N)";


if(description)
{
 script_id(12234);
 script_version ("$Revision: 1.5 $");
 
 name["english"] = "Terminal Services Web Detection";
 script_name(english:name["english"]);
 

 script_description(english:desc["english"]);
 
 summary["english"] = "Find instances of tsweb";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");

 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "no404.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);


# So, we'll first just check for http://<host>/tsweb/
# 9 times out of 10, you'll find it in this location

req = http_get(item:string("/tsweb/"),
                 port:port);
buf = http_keepalive_send_recv(port:port, data:req);
if(egrep(pattern:"const L_DisconnectedCaption_ErrorMessage", string:buf)) {

	report = string (desc["english"],
		"\n\nPlugin output :\n\n",
		"The following directory should provide a useful resource in your\n",
		"pen-testing endeavors:\n",
		string("http://", get_host_ip() , "/tsweb/", "\n"));

        security_note(port:port, data:report);
        exit(0);
}





# Next, we'll roll through each of the cgi_dirs and check for either 
# /tsweb/<default page> or /tsweb.asp

foreach d (cgi_dirs()) {
    req = http_get(item:string(d, "/tsweb.asp"),
                 port:port);
    req2 = http_get(item:string(d, "/tsweb/"),
                 port:port);

    buf = http_keepalive_send_recv(port:port, data:req);
    buf2 = http_keepalive_send_recv(port:port, data:req2);

    if(egrep(pattern:"const L_DisconnectedCaption_ErrorMessage", string:buf)) {
	report = string (desc["english"],
		"\n\nPlugin output :\n\n",
		"The following directory should provide a useful resource in your\n",
		"pen-testing endeavors:\n",
		string("http://", get_host_ip() , d, "\n"));

        security_note(port:port, data:report);
        exit(0);
    }

    if(egrep(pattern:"const L_DisconnectedCaption_ErrorMessage", string:buf2)) {
 	report = string (desc["english"],
		"\n\nPlugin output :\n\n",
		"The following directory should provide a useful resource in your\n",
		"pen-testing endeavors:\n",
		string("http://", get_host_ip() , d, "/tsweb/", "\n"));

        security_note(port:port, data:report);
        exit(0);
    }

}


