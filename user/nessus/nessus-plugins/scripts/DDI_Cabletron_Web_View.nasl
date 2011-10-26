#
# This script was written by Forrest Rae
#

if(description)
{
	script_id(10962);
	script_version ("$Revision: 1.8 $");
        # script_cve_id("CVE-MAP-NOMATCH");
# NOTE: reviewed, and no CVE id currently assigned (jfs, december 2003)
 
 	name["english"] = "Cabletron Web View Administrative Access";
 	script_name(english:name["english"]);
 
	desc["english"] = "
This host is a Cabletron switch and is running 
Cabletron WebView. This web software 
provides a graphical, real-time representation of 
the front panel on the switch. This graphic, 
along with additionally defined areas of the 
browser interface, allow you to interactively 
configure the switch, monitor its status, and 
view statistical information. An attacker can 
use this to gain information about this host.

Solution: Depending on the location of the switch, it might 
be advisable to restrict access to the web server by IP 
address or disable the web server completely.

Risk factor : High";   

	script_description(english:desc["english"]);
 	summary["english"] = "Cabletron Web View Administrative Access";
	script_summary(english:summary["english"]);
	script_category(ACT_GATHER_INFO);
	script_copyright(english:"This script is Copyright (C) 2002 Digital Defense Incorporated");
	family["english"] = "Misc.";
	script_family(english:family["english"]);
	script_dependencie("find_service.nes");
    script_require_ports("Services/www");
	exit(0);
}

include("http_func.inc");

port = get_http_port(default:80);


if(get_port_state(port))
{
	soc = http_open_socket(port);
	if(soc)
	{
		req = http_get(item:string("/chassis/config/GeneralChassisConfig.html"), port:port);
		send(socket:soc, data:req);
		
		r = http_recv(socket:soc);
		     
		if("Chassis Configuration" >< r)
		{
			security_hole(port:port); 
			set_kb_item(name:"Services/www/" + port + "/embedded", value:TRUE);
			exit(0);
		}

		http_close_socket(soc);
	}
}



