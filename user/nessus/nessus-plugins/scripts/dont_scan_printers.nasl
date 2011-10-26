# This script was written by Michel Arboi <arboi@alussinan.org>
#
# Released under GPLv2
#

if(description)
{
 script_id(11933);
 script_version ("$Revision: 1.31 $");
 name["english"] = "Do not scan printers";
 script_name(english:name["english"]);

 desc["english"] = "
Synopsis :

The host seems to be a printer. The scan has been disabled against this host.

Description :

Many printers react very badly to a network scan. Some of them will crash, 
while others will print a number of pages. This usually disrupt office work
and is usually a nuisance. As a result, the scan has been disabled against this
host.

Solution :

If you want to scan the remote host, disable the 'safe checks' option and
re-scan it.

Risk factor : 

None / CVSS Base Score : 0
(AV:L/AC:H/Au:R/C:N/A:N/I:N/B:N)";

 script_description(english:desc["english"]);

 summary["english"] = "Exclude AppSocket & socketAPI printers from scan";
 script_summary(english:summary["english"]);

 script_category(ACT_SETTINGS);

# script_add_preference(name:"Exclude printers from scan", type:"checkbox", value:"no");

 script_copyright(english:"This script is Copyright (C) 2003 by Michel Arboi");
 family["english"] = "Settings";	
# Or maybe a "scan option" family?
 script_family(english:family["english"]);
 script_dependencie("dont_scan_settings.nasl");
 exit(0);
}


include("ftp_func.inc");
include("telnet_func.inc");
include("http_func.inc");
include("snmp_func.inc");
include("global_settings.inc");

if ( get_kb_item("Scan/Do_Scan_Printers" ) ) exit(0);

if ( get_kb_item("SNMP/community") )
{
 port = get_kb_item("SNMP/port"); 
 community = get_kb_item("SNMP/community");
 soc = open_sock_udp (port);
 if (  soc ) 
 {
  desc = snmp_request(socket:soc, community:community, oid:"1.3.6.1.2.1.1.1.0");
  if ( desc && (("JETDIRECT" >< desc) || ("OKI OkiLAN" >< desc) || ("LaserJet" >< desc) || ("Xerox Phaser" >< desc) || ("Xerox DocuColor" >< desc) || ("Canon iR" >< desc) || ("Xerox WorkCentre" >< desc) || ("Lantronix MSS100" >< desc) ) )
   {
    set_kb_item(name: "Host/dead", value: TRUE);
    security_note(port: 0);
    exit(0);
   }
  desc = snmp_request(socket:soc, community:community, oid:"1.3.6.1.2.1.1.4.0");
  if ( desc && "JETDIRECT" >< desc )
   {
    set_kb_item(name: "Host/dead", value: TRUE);
    security_note(port: 0);
    exit(0);
   }
  close(soc);
 }
}



# First try UDP AppSocket

if ( get_kb_item("Host/scanned")  == 0 ) exit(0);

port = 9101;
if (get_udp_port_state(port))
{
  soc = open_sock_udp(port);

  send(socket: soc, data: '\r\n');
  r = recv(socket: soc, length: 512);
  if (r)
  {
    set_kb_item(name: "Host/dead", value: TRUE);
    if (debug_level) display(get_host_ip(), " answers to UDP AppSocket\n");
    security_note(port: 0);
    exit(0);
  }
}

port = 21;
if(get_port_state(port))
{
 banner = get_ftp_banner(port:port);
 if("JD FTP Server Ready" >< banner)
 {
    set_kb_item(name: "Host/dead", value: TRUE);
    if (debug_level) display(get_host_ip(), " runs JD FTP server\n");
    security_note(port: 0);
    exit(0);
 }
 else if ("220 Dell Laser Printer " >< banner)
 {
    set_kb_item(name: "Host/dead", value: TRUE);
    if (debug_level) display(get_host_ip(), " runs Dell FTP server\n");
    security_note(port: 0);
    exit(0);
 }
 else if ( egrep(pattern:"^220 DPO-[0-9]+ FTP Server", string:banner) )
 {
    set_kb_item(name: "Host/dead", value: TRUE);
    if (debug_level) display(get_host_ip(), " Toshiba Printer\n");
    security_note(port: 0);
    exit(0);
 }
 else if ( egrep(pattern:"^220 .* Lexmark.* FTP Server", string:banner) )
 {
    set_kb_item(name: "Host/dead", value: TRUE);
    if (debug_level) display(get_host_ip(), " Lexmark Printer\n");
    security_note(port: 0);
    exit(0);
 }
 else if ("220 Print Server Ready." >< banner)
 {
  set_kb_item(name: "Host/dead", value: TRUE);
  security_note(port: 0);
  exit(0);
 }
}

port = 23;
if(get_port_state(port))
{
 banner = get_telnet_banner(port:port);
 if("HP JetDirect" >< banner)
 {
    set_kb_item(name: "Host/dead", value: TRUE);
    if (debug_level) display(get_host_ip(), " runs HP JetDirect telnet server\n");
    security_note(port: 0);
    exit(0);
 }
 if("RICOH Maintenance Shell" >< banner)
 {
    set_kb_item(name: "Host/dead", value: TRUE);
    if (debug_level) display(get_host_ip(), " runs RICOH Printer telnet server\n");
    security_note(port: 0);
    exit(0);
 }
}
# Xerox DocuPrint
port = 2002;
if ( get_port_state(port) )
{
 soc = open_sock_tcp(port);
 if ( soc )
 {
  banner = recv(socket:soc, length:23);
  close(soc);
  if ( banner && 'Please enter a password' >< banner ) {
    	set_kb_item(name: "Host/dead", value: TRUE);
    	security_note(port: 0);
	exit(0);
	}
 }
}

# Lexmark Optra returns on finger port:
# Parallel port 1
# Printer Type: Lexmark Optra LaserPrinter
# Print Job Status: No Job Currently Active
# Printer Status: 0 Ready

port = 79;
if (get_port_state(port))
{
 soc = open_sock_tcp(port);
 if (soc)
 {
   banner = recv(socket:soc, length: 512);
   if (strlen(banner) == 0)
   {
    send(socket: soc, data: 'HELP\r\n');
    banner = recv(socket:soc, length: 512);
   }
   close(soc);
   if (banner && 'Printer type:' >< banner)
   {
     set_kb_item(name: "Host/dead", value: TRUE);
     security_note(port: 0);
     exit(0);
   }
  }
}


# Patch by Laurent Facq
ports = make_list(80, 280, 631);
foreach port (ports)
{
 if(get_port_state(port))
 {
  banner = http_send_recv(port:port, data:string("GET / HTTP/1.1\r\n\r\n"));
  if("Dell Laser Printer " >< banner )
  {
     set_kb_item(name: "Host/dead", value: TRUE);
    if (debug_level) display(get_host_ip(), " runs Dell web server\n");
     security_note(port: 0);
     exit(0);
  }
  else if( ("<title>Hewlett Packard</title>" >< banner) || ("LaserJet" >< banner) )
  {
     set_kb_item(name: "Host/dead", value: TRUE);
    if (debug_level) display(get_host_ip(), " runs HP web server\n");
     security_note(port: 0);
     exit(0);
  }
  else if ( banner && "Server: Xerox_MicroServer/Xerox" >< banner )
  {
     set_kb_item(name: "Host/dead", value: TRUE);
    if (debug_level) display(get_host_ip(), " runs a Xerox web server\n");
    security_note(port: 0);
    exit(0);
  }
  else if ( banner && ("Server: Rapid Logic/" >< banner ||
                       "Server: Virata-EmWeb" >< banner ) )
  {
     set_kb_item(name: "Host/dead", value: TRUE);
    if (debug_level) display(get_host_ip(), " runs a HP printer\n");
    security_note(port: 0);
    exit(0);
  }
 else if(banner && "Fiery" >< banner )
  {
    set_kb_item(name: "Host/dead", value: TRUE);
    if (debug_level) display(get_host_ip(), " runs Fiery WebTools\n");
    security_note(port: 0);
    exit(0);
  }
 }
}


# open ports?
ports = get_kb_list("Ports/tcp/*");
# Host is dead, or all ports closed, or unscanned => cannot decide
if (isnull(ports)) exit(0);
# Ever seen a printer with more than 8 open ports?
# if (max_index(ports) > 8) exit(0);

# Test if open ports are seen on a printer
# http://www.lprng.com/LPRng-HOWTO-Multipart/x4981.htm
appsocket = 0;


foreach p (keys(ports))
{
  p = int(p - "Ports/tcp/");
  if (	   p == 35		# AppSocket for QMS
	|| p == 2000		# Xerox
	|| p == 2501		# AppSocket for Xerox
	|| (p >= 3001 && p <= 3005)	# Lantronix - several ports
	|| (p >= 9100 && p <= 9300)	# AppSocket - several ports
#        || p == 10000 		# Lexmark
	|| p == 10001)		# Xerox - programmable :-(
    appsocket = 1;
# Look for common non-printer ports
	 else if (
          p != 21              # FTP
       && p != 23              # telnet
       && p != 79
       && p != 80              # www
       && p != 139 && p!= 445  # SMB
       && p != 280             # http-mgmt
       && p != 443
       && p != 515             # lpd
       && p != 631 	       # IPP
       && p != 8000 
       && (p < 5120 || p > 5129))  # Ports 512x are used on HP printers    
	exit(0);

}


# OK, this might well be an AppSocket printer
if (appsocket)
{
  security_note(0);
  if (debug_level) display(get_host_ip(), " looks like an AppSocket printer\n");
  set_kb_item(name: "Host/dead", value: TRUE);
}
