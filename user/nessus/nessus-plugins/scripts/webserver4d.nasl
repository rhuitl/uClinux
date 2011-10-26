# This script was created by Jason Lidow <jason@brandx.net>
# The vulnerability was originally discovered by ts@securityoffice.net 


if(description)
{
        script_id(11151);
        script_bugtraq_id(5803);
	script_cve_id("CVE-2002-1521");
        script_version("$Revision: 1.7 $");
        script_name(english:"Webserver 4D Cleartext Passwords");


    script_description(english:"
The remote host is running Webserver 4D 3.6 or lower.
  
Version 3.6 of this service stores all usernames and passwords in cleartext. 
File: C:\Program Files\MDG\Web Server 4D 3.6.0\Ws4d.4DD

A local attacker may use this flaw to gain unauthorized privileges
on this host.


Solution: Contact http://www.mdg.com for an update.        
Risk Factor: Low");


        script_summary(english:"Checks for Webserver 4D");


        script_category(ACT_GATHER_INFO);


        script_copyright(english:"This script is Copyright (C) 2002 Jason Lidow <jason@brandx.net>");
        script_family(english:"Misc.");
        script_dependencie("find_service.nes", "httpver.nasl", "no404.nasl");
        script_require_ports("Services/www", 80);
        exit(0);
}


include("http_func.inc");
port = get_http_port(default:80);


banner = get_http_banner(port:port);


poprocks = egrep(pattern:"^Server.*", string: banner);
if(banner)
{
        if("Web_Server_4D" >< banner) 
	{
                yo = string("The following banner was received: ", poprocks, "\n\nVersion 3.6 and lower of Webserver 4D stores all usernames and passwords in cleartext.\n\nFile: C:\\Program Files\\MDG\\Web Server 4D 3.6.0\\Ws4d.4DD\n\nRisk Factor: Low\nSolution: Contact http://www.mdg.com for an update.");
                security_note(port:port, data:yo);
 	}
}
