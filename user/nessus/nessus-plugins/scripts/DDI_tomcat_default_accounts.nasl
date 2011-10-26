#
# This script was written by Orlando Padilla <orlando.padilla@digitaldefense.net>
#
# See the Nessus Scripts License for details
#

if (description)
{
   script_id(11204);
   script_version("$Revision: 1.10 $");
   script_cve_id("CVE-1999-0508");
   name["english"] = "Apache Tomcat Default Accounts";
   script_name(english:name["english"]);


   desc["english"] = "
    
This host appears to be the running the Apache Tomcat
Servlet engine with the default accounts still configured.
A potential intruder could reconfigure this service in a way
that grants system access.

Solution: Change the default passwords by editing the 
          admin-users.xml file located in the /conf/users
          subdirectory of the Tomcat installation.

Risk factor : High";

    script_description(english:desc["english"]);

    summary["english"] = "Apache Tomcat Default Accounts";
    script_summary(english:summary["english"]);


    script_category(ACT_ATTACK);

    script_copyright( english:"This script is Copyright (C) 2003 Digital Defense Inc.",
                      francais:"Ce script est Copyright (C) 2003 Digital Defense Inc.");

    family["english"] = "Web Servers";

    script_family(english:family["english"]);
    script_dependencie("find_service.nes", "http_version.nasl");
    script_require_ports("Services/www");
    exit(0);
}

#
# The script code starts here
#
include("http_func.inc");

port = get_http_port(default:8080);
if ( ! port ) exit(0);

banner = get_http_banner(port:port);
if ( "Tomcat" >!< banner ) exit(0);

#assert on init
flag=1;

#list of default acnts base64()'d
auth[0]=string("YWRtaW46Y2hhbmdldGhpcw==\r\n\r\n");	real_auth[0]=string("admin:tomcat");
auth[1]=string("YWRtaW46dG9tY2F0Cg==\r\n\r\n");	real_auth[1]=string("admin:admin");
auth[2]=string("YWRtaW46YWRtaW4K\r\n\r\n");		real_auth[2]=string("tomcat:tomcat");
auth[3]=string("dG9tY2F0OnRvbWNhdAo=\r\n\r\n");	real_auth[3]=string("admin:tomcat");
auth[4]=string("cm9vdDpyb290Cg==\r\n\r\n");		real_auth[4]=string("root:root");
auth[5]=string("cm9sZTE6cm9sZTEK\r\n\r\n");		real_auth[5]=string("role1:role1");
auth[6]=string("cm9sZTpjaGFuZ2V0aGlzCg==\r\n\r\n");	real_auth[6]=string("role:changethis");
auth[7]=string("cm9vdDpjaGFuZ2V0aGlzCg==\r\n\r\n");	real_auth[7]=string("root:changethis");
auth[8]=string("dG9tY2F0OmNoYW5nZXRoaXMK\r\n\r\n");	real_auth[8]=string("tomcat:changethis");
auth[9]=string("eGFtcHA6eGFtcHA=\r\n\r\n");		real_auth[9]=string("xampp:xampp");


#basereq string
basereq = http_get(item:"/admin/contextAdmin/contextList.jsp", port:port);
basereq = basereq - string("\r\n\r\n");


authBasic=string("Authorization: Basic ");

i = 0;
found = 0;
report = string("");

if(get_port_state(port))
{
	if(http_is_dead(port:port))exit(0);
	
	# Check that we need any authorization at all
	soc = http_open_socket(port);
	if(!soc)exit(0);
	send(socket:soc, data:http_get(item:"/admin/contextAdmin/contextList.jsp", port:port));
	rs = http_recv(socket:soc);
	
	http_close_socket(soc);
	if(!ereg(pattern:"^HTTP/1\.[0-1] 401 ", string:rs))exit(0);
	if(("<title>Context list</title>" >< rs) || ("<title>Context Admin</title>" >< rs))exit(0);
	
	
	while( auth[i] )
	{
	 soc = http_open_socket(port);
	 if(soc)
	 {
	   t0 = basereq;
	   t1 = authBasic;
	   t1 = string(t1,auth[i]);
	   t0 = string(t0,t1);

	   send(socket:soc,data:t0);
       
	   rs = http_recv(socket:soc);
	   
       # minor changes between versions of jakarta
	   if(("<title>Context list</title>" >< rs) || ("<title>Context Admin</title>" >< rs))
	   { 
		found = found + 1;
		if(found == 1)
			report = string("The following accounts were discovered: \n",real_auth[i], "\n");
		else {
			report = string(report, string(real_auth[i], "\n"));
		}
	   }
	   http_close_socket(soc);
	   i=i+1;	   
	  }
	}
}

# should we include the plugin description?
if (found)
{
	security_hole(port:port,data:report);
}
