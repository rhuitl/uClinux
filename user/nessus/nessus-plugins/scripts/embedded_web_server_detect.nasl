#
# (C) Tenable Network Security
#
# This script is released under the GPLv2
#

if(description)
{
 script_id(19689);
 script_version("$Revision: 1.21 $");
 
 name["english"] = "Embedded Web Server Detection";

 script_name(english:name["english"]);
 
 desc["english"] = "
This plugin determines if the remote web server is an embedded service 
(without any user-supplied CGIs) or not

Risk factor : None";

 script_description(english:desc["english"]);
 
 summary["english"] = "This scripts detects wether the remote host is an embedded web server";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 TNS");
 
 family["english"] = "Misc.";
 script_family(english:family["english"]);
 script_dependencies("cisco_ids_manager_detect.nasl", "ciscoworks_detect.nasl",
"clearswift_mimesweeper_smtp_detect.nasl", "imss_detect.nasl", "interspect_detect.nasl", "intrushield_console_detect.nasl",
"iwss_detect.nasl", "linuxconf_detect.nasl", "securenet_provider_detect.nasl",
"tmcm_detect.nasl", "websense_detect.nasl", "xedus_detect.nasl", "xerox_document_centre_detect.nasl", "xerox_workcentre_detect.nasl", "compaq_wbem_detect.nasl");

 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");


port = get_kb_item("Services/www");
if ( ! port ) exit(0);

if ( get_kb_item("Services/www/" + port + "/embedded") ) exit(0);

banner = get_http_banner(port:port);
if ( ! banner ) exit(0);

if (egrep(pattern:"^(DAAP-)?[Ss]erver: (CUPS|MiniServ|AppleShareIP|Embedded HTTPD|IP_SHARER|Ipswitch-IMail|MACOS_Personal_Websharing|NetCache appliance|(ZyXEL-)?RomPager/|cisco-IOS|u-Server|eMule|Allegro-Software-RomPager|RomPager|Desktop On-Call|D-Link|4D_WebStar|IPC@CHIP|Citrix Web PN Server|SonicWALL|Micro-Web|gSOAP|CompaqHTTPServer/|BBC [0-9.]+; .*[cC]oda|HP-Web-JetAdmin|Xerox_MicroServer|HP-ChaiServer|Squid/Alcatel|HTTP Server$|Virata-EmWeb|RealVNC|gSOAP|dncsatm|Tandberg Television Web server|Service admin/|Gordian Embedded|eHTTP|SMF|Allegro-Software-RomPager|3Com/|SQ-WEBCAM|WatchGuard Firewall|Acabit XML-RPC Server|SonicWALL|EWS-NIC|3ware/|RAC_ONE_HTTP|GoAhead|BBC|CCM Desktop Agent|iTunes/)", string:banner) ||
    port == 901 )
 	{
	set_kb_item(name:"Services/www/" + port + "/embedded", value:TRUE);
	}

