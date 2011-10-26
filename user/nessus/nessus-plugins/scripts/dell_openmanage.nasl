#
# Plugin written by Tomi Hanninen <Tomi.Hanninen@thermo.com>
# 
# GPL
#
# ref: http://sh0dan.org/files/domadv.txt

if(description)
{
	script_id(12295);
	script_cve_id("CVE-2004-0331");
	script_bugtraq_id(9750);
  	script_version("$Revision: 1.9 $");
	name["english"] = "Dell OpenManage Web Server <= 3.7.1";
	script_name(english:name["english"]);

	desc["english"] = "
The remote host is running the Dell OpenManage Web Server.

Dell OpenManage Web Servers 3.2.0-3.7.1 are vulnerable to a heap based 
buffer overflow attack. A proof of concept denial of service attack has been 
released.

*** Note : The Dell patch does not increase the version number of this service
*** so this may be a false positive

Patch is available at http://support.dell.com/filelib/download.asp?FileID=96563&c=us&l=en&s=DHS&Category=36&OS=WNT5&OSL=EN&SvcTag=&SysID=PWE_FOS_XEO_6650&DeviceID=2954&Type=&ReleaseID=R74029

See also : http://sh0dan.org/files/domadv.txt
Solution : Install the security patch available from Dell 
Risk factor : High";

	script_description(english:desc["english"]);

	summary["english"] = "Dell OpenManage Web Server 3.2.0-3.7.1 are vulnerable to a heap based buffer overflow";

	script_summary(english:summary["english"]);
	script_family(english:"Denial of Service");

	script_copyright(english:"This is script is Copyright (C) 2004 Tomi Hanninen");
	script_require_ports(1311);
	script_category(ACT_GATHER_INFO);
exit(0);
}

#
# Actual script
#

include("http_func.inc");
include("http_keepalive.inc");

port = 1311;

if ( ! get_port_state(port) ) exit(0);

soc = open_sock_tcp(port, transport:ENCAPS_SSLv23);


url = "/servlet/UDataArea?plugin=com.dell.oma.webplugins.AboutWebPlugin";
request = http_get(port:port, item:url);

if(soc)
{	
	send(socket:soc, data:request);
	buffer = http_recv(socket:soc);
	close(soc);
	
	# This will search for the version line
	# it _should_ match versions 3.2.0-3.6.9 and 3.7.0
	if ( egrep(pattern:"<br>Version ([0-2]\.|3\.[2-6]\.)|(3\.7\.[0-1])<br>", string:buffer) ) 
	 {
	   security_hole(port); 
	 } 
}
