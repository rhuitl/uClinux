#
# (C) 2003 Tenable Network Security
#
# Redistribution and use in source, with or without modification, are 
# permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. All advertising materials mentioning features or use of this software
#    must display the following acknowledgement:
#     This product includes software developed by Tenable Network Security
#
#
#
# grep ":.*:.*:.*:.*:.*:.*:.*:.*:.*:.*:" os_fingerprint.nasl | sort  | uniq -c  | sort -n
#
#
# The following persons contributed signatures :
#
# 'Securite Antivirus' (ac-besancon)
# 13dka
# Aaron Smith
# Aaron Wickware
# Abri Du Plooy
# Adam LaFrenier
# Adrian S Voinea
# Ahmet Ozturk
# Aldwin Wijnveld
# Alexander Brinkman - IRIX 6.5.20
# Alonso Torres
# Anders Oreback
# Andrew Cox
# Andy Tuck
# Anthony Tulio
# Arnod Nipper
# Arnold Nipper
# Audun Larsen
# AV
# Benjam Figon
# Benjamin Zak
# Bill Jackson
# Bill Petersen
# Billy Holmes
# Bjarke Christesen
# Boka Marek
# Boris Bielous
# Brian Costello
# Brian Haney
# Burt Soltero
# CWL Hoogenboezem
# Calvin Garrison
# Carl Houseman
# Carlo Tognetti
# Chad Goldman
# ChazeFroy
# Charles G Griebel
# Chris Gamboni
# Chris Karr
# Chris Sullo
# Christoph Wenger
# Christopher Walsh
# Clifford A. Collins
# Clyde Hoadley
# Craig Carpenter
# Dan Kennedy
# Dane Howard
# Daniel Griswold
# Daniel Moreland
# Daniel Surdu
# Daniel Wesemann
# Dave
# Dave Nelson
# David
# David A. Koran
# David C. Papayoanou
# David Lodge
# David Panofsky
# Dead Jester
# Dennis Feijen
# Dirk De Wit
# Don Hartzog
# Donald A. Tevault
# Donald J. Ankney
# Ego Kastelijin
# Enno Rey
# Eric Pinkerton
# Erik Ball
# Erik Brostrm
# Erik Linder
# Eugene
# Evan Wunderle
# Fabio Erri
# Fazer
# Florian Huber
# Florin Mariutea
# Francis Souza
# Frank Reid
# Gareth Rhys
# Garry Frazer
# Gary Boardman
# Gauthier Lulka
# Gavin Atkinson
# Geoff King
# George Theall
# Georgi Vodenitcharov
# Gerardo Di Giacomo
# Giulio Marchionni
# Goran Tornqvist
# Graham Freeman
# Greg Roelofs
# Guy RayMakers
# H D Moore
# Hal Davis
# Heiko Geist
# Heinze Kluge
# Herbert Rosenau
# HoJoToGo
# Ian Anderson
# Ian Comerford
# Ian Parker
# Ian Pattison
# JKalf
# Jakob Staerk
# Jamyn
# Jason Dravet
# Jason Mock
# Jay Reffner
# Jeff Groves
# Jeiff Schneider
# Jim Cassata
# Jim Jackson
# Jim Southwell
# Joah Sorliden
# Joannathan Hervé
# Joe Clifton
# Joe McKinnon
# Joel (asmodianx)
# Johan Srilden
# John Ward
# Joshua Broussard
# Joshua Voigt
# Juan Carlo Matain
# Julio M. Merino Vidal
# Justin Wienckow
# Jutta Zalud
# KK Liu
# Kai Hofmann
# Keith Duarte
# Ken Welker
# Kendall Risselada
# Kenneth Kidd
# Kevin
# Kevin McPhillipps
# Kjeld Dunweber
# Knut Ut
# Kulbinder S Kalirai
# Kurt Mosiejczuk
# Kyle Barz
# Lance Lloyd
# Lee Reynolds
# Lior Rotkovitch
# Luigi Rosa
# Luke Hitch
# Maarten Hartsuijker
# Maarten Hartsuikjker
# Mally Mclane
# Marc Jacquard
# Marc Nowak
# Marc at spooshland.com
# Marcelo Oliveira
# Marco IANNOZI
# Marco Teixeira
# Mark Anders
# Mark Basset
# Martin Kown
# Martin Leung
# Mason Brown
# Matt Wilkins
# Matthew Gream
# Matthias Geiser
# Mattias Dewulf
# Mattias Webjorn Eriksson
# Maximilian Eul
# Michael H Busse
# Michael K. Smith
# Michael Mauch
# Michael Scheidell
# Michael Tsentsarevsky
# Michael Wittauer
# Michel Arboi
# Mikael Andersson
# Mike Burton
# Mike Leahy
# Montgomery County Maryland
# Neil McElhinney
# Nick Nero
# Nicolas Nerson
# Nicolas S. Dade
# Olivier Marechal
# Ondrej Cecak
# Owen Crow
# Pablo Emilio
# Par Turesson
# Pardazeh Eng Co
# Patrick Davignon
# Patrick O'connor
# Paul Gibson
# Paul Kuhanst
# Paul Lamb
# Paul MacLennan
# Paul Shelbourn
# Paul Weatherhead
# Pauli Borodolin
# Pauli Borodulin
# Pauli Burodulin
# Pauli Porodulin
# Pavel Vachek
# Pedro Andujar
# Petar Krasmirov
# Peter Dilling
# Peter Eckel
# Peters Devon
# Philippe Deschamp
# Philippe Lang
# Piotr Lasota
# Ragis Guirguis
# Ral Aldaz
# Ralph Utz
# Randy Jones
# Randy Towry
# Renato Schmidt
# Renaud Fortier
# Ricardo Stella
# Rich
# Richard Harvey
# Richard Shinebarger
# Rick Klaasen
# Riley Nice
# Robert Casey
# Roberto Marinello
# Rodik
# Roman Rodak
# Ron Searle
# Ronish Mehta
# Ruslan Savshyn
# Ryan Tryssenaar
# Ryan Tryssernaar
# Scott Bentley
# Scott Stanton
# Sean Buffington
# Sean O'Brian
# Sergy Osipov
# Shane Mullins
# Shawn Leard
# Shawn Lukaschuk
# Simon Fretz
# Skyler Bingham
# Slim Amamou
# Stephen B Suddeth
# Stephen Weeber
# Steve Sanders
# Steve Wielgus
# Steven Lim
# Stuart Halliday
# Sumit Khanna
# Thomas Karsten Bauer
# Thomas Ratz
# Tobias Glemser
# Tobias Reichl
# Todd
# Todd H
# Victor M. Forno J.
# Vincent Renardias
# W. Anderson
# Wany Barber
# Wayne Barber
# William D. Johnson
# William Riley
# Wood McBain
# Yoni
# Zube
# alzeke
# fr3ak
# jiang zuowen
# nts
# omri
# rewriteit
# rio@rio.st
#
#
#
 

if (description)
{
  script_version("$Revision: 1.138 $");
  script_id(11936);

  name["english"] = "OS Identification";
  script_name(english:name["english"]);

  desc["english"] = "
This script attempts to identify the Operating System type and version by
various ways :

- If the remote host is a Windows host, it will attempt to determine its
  OS type by sending MSRPC packets on port 135 and guess the OS based on
  the results

- If the remote host has an NTP client listening on port 123, this script will
  try to ask for the operating system version this way

- Otherwise, this script determines the remote operating system by sending more 
or less incorrect ICMP requests using the techniques outlined in Ofir Arkin's 
paper 'ICMP Usage In Scanning'.

An attacker may use this to identify the kind of the remote operating
system and gain further knowledge about this host.

See also : http://www.sys-security.com/html/projects/icmp.html (icmp os identification)
Risk factor : Low";

  script_description(english:desc["english"]);
 
  summary["english"] = "Determines the remote operating system";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
 
  script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
  family["english"] = "General";
  script_family(english:family["english"]);
  script_dependencies("smb_hotfixes.nasl", "ntp_open.nasl", "mdns.nasl", "snmp_sysDesc.nasl");
  script_require_ports(139, 445, "Host/scanned");
  exit(0);
}



include('global_settings.inc');
include("network_func.inc");
include("smb_nt.inc");
include("raw.inc");


if ( content = get_kb_item("SMB/ProdSpec") )
{
  product = egrep(pattern:"^Product=", string:strstr(content, "Product="));
  lang    = egrep(pattern:"^Localization=", string:strstr(content, "Localization="));
  if (strlen(product)) {
	 product -= "Product=";
         end = strstr(product, '\n');
         product = product - end;
	 lang    -= "Localization=";
	 end = strstr(lang, '\n');
	 lang = lang - end;
	 if ( "Service Pack" >!< sp ) sp = "";
         else sp = " " + sp ;
	 version = "Microsoft " + product + sp + " (" + lang + ")";
         report = "The remote host is running " + version;
         set_kb_item(name:"Host/OS/icmp", value:version);
         security_note(port:0, data: report );
         exit(0);
       }
} 


if ( (os = get_kb_item("mDNS/os")) )
{
         report = "The remote host is running " + os;
         set_kb_item(name:"Host/OS/icmp", value:os);
	 security_note(port:0, data:report);
	 exit(0);
}

if ( ( os = get_kb_item("SNMP/sysDesc")) ) 
{
 if ( "ZyWALL" >< os )
 {
  os = "ZyXEL ZyWALL Security Appliance";
  report = "The remote host is running " + os;
  set_kb_item(name:"Host/OS/icmp", value:os);
  security_note(port:0, data:report);
  exit(0);
 }
 if ( "Lexmark" >< os )
 {
  os = "Lexmark Printer";
  report = "The remote host is running " + os;
  set_kb_item(name:"Host/OS/icmp", value:os);
  security_note(port:0, data:report);
  exit(0);
 }
 if ( "Fiery " >< os )
 {
  os = "Minolta Fiery Copier";
  report = "The remote host is running " + os;
  set_kb_item(name:"Host/OS/icmp", value:os);
  security_note(port:0, data:report);
  exit(0);
 }
 if ( "TOSHIBA e-STUDIO" >< os )
 {
  os = "Toshiba e-Studio printer";
  report = "The remote host is running " + os;
  set_kb_item(name:"Host/OS/icmp", value:os);
  security_note(port:0, data:report);
  exit(0);
 }
 if ( "Dell Out-of-band SNMP" >< os )
 {
  os = "Dell Remote Access Controller";
  report = "The remote host is running " + os;
  set_kb_item(name:"Host/OS/icmp", value:os);
  security_note(port:0, data:report);
  exit(0);
 }

 if ("TigerStack" >< os )
 { 
  os = "SMC TigerStack Switch";
  report = "The remote host is running " + os;
  set_kb_item(name:"Host/OS/icmp", value:os);
  security_note(port:0, data:report);
  exit(0);
 }
 if ("Dell Laser Printer " >< os )
 { 
  os = "Dell Laser Printer";
  report = "The remote host is running " + os;
  set_kb_item(name:"Host/OS/icmp", value:os);
  security_note(port:0, data:report);
  exit(0);
 }
 if ( "Prisma Digital Transport" >< os ) 
 {
   os = "Prisma Digital Transport System";
   report = "The remote host is running " + os;
   set_kb_item(name:"Host/OS/icmp", value:os);
   security_note(port:0, data:report);
   exit(0);
 }
 if ( "RICOH Network Printer C model" >< os )
 {
   os = "Ricoh Printer";
   report = "The remote host is running " + os;
   set_kb_item(name:"Host/OS/icmp", value:os);
   security_note(port:0, data:report);
   exit(0);
 }
 if ( "CMTS" >< os && "Juniper Networks Inc." >< os )
 {
   os = "Juniper CMTS";
   report = "The remote host is running " + os;
   set_kb_item(name:"Host/OS/icmp", value:os);
   security_note(port:0, data:report);
   exit(0);
 }
 if ("Chkpoint/LTX" >< os )
 {
   os = "Checkpoint/Lantronix Network Adaptor";
   report = "The remote host is running " + os;
   set_kb_item(name:"Host/OS/icmp", value:os);
   security_note(port:0, data:report);
   exit(0);
 }
 if ("Konica IP Controller" >< os )
  {
   os = "Konica IP Controller";
   report = "The remote host is running " + os;
   set_kb_item(name:"Host/OS/icmp", value:os);
   security_note(port:0, data:report);
   exit(0);
  }
 if ("Marconi ASX" >< os )
  {
   os = "Marconi ASX Switch";
   report = "The remote host is running " + os;
   set_kb_item(name:"Host/OS/icmp", value:os);
   security_note(port:0, data:report);
   exit(0);
  }
 if ("CoreBuilder 3500" >< os )
  {
   os = "3Com CoreBuilder 3500 Switch";
   report = "The remote host is running " + os;
   set_kb_item(name:"Host/OS/icmp", value:os);
   security_note(port:0, data:report);
   exit(0);
  }
 if ("Ascend Max-HP" >< os )
  {
   version = ereg_replace(pattern:"Software \+([0-9.]*)\+.*", string:os, replace:"\1");
   os = "Ascend Max-HP Modem Hub " + version;
   report = "The remote host is running " + os;
   set_kb_item(name:"Host/OS/icmp", value:os);
   security_note(port:0, data:report);
   exit(0);
  }
 if ("LVisual UpTime Multiprotocol T1 CSU DROP & INSERT ASE Ver" >< os )
 {
   version = ereg_replace(pattern:".* ASE Ver ([0-9.]*) .*", string:os, replace:"\1");
   os = "Visual Networks ASE " + version;
   report = "The remote host is running " + os;
   set_kb_item(name:"Host/OS/icmp", value:os);
   security_note(port:0, data:report);
   exit(0);
 }
 if ("ELSA LANCOM" >< os )
 {
   report = "The remote host is running " + os;
   set_kb_item(name:"Host/OS/icmp", value:os);
   security_note(port:0, data:report);
   exit(0);
 }
 if ("IP Console Switch " >< os )
 {
  report = "The remote host is running HP " + os;
   set_kb_item(name:"Host/OS/icmp", value:"HP " + os);
   security_note(port:0, data:report);
   exit(0);
 }
 if ("SCO UnixWare" >< os )
 {
   report = "The remote host is running " + os;
   set_kb_item(name:"Host/OS/icmp", value:os);
   security_note(port:0, data:report);
   exit(0);
 }

 if ("Apple Base Station" >< os )
 {
   version = ereg_replace(pattern:".*Apple Base Station V(.*) Compatible",
			  replace:"\1",
			  string:os);
 
   os = "Apple Airport " + version;
   report = "The remote host is running " + os;
   set_kb_item(name:"Host/OS/icmp", value:os);
   security_note(port:0, data:report);
   exit(0);
 }
 if ("OpenVMS" >< os )
 {
  version = ereg_replace(pattern:".*OpenVMS V([0-9]*\.[0-9]*).*", 
			 string:egrep(pattern:"OpenVMS", string:os),
			 replace:"\1");
  if ( version != os )
  {
   os = "OpenVMS " + version;
   report = "The remote host is running " + os;
   set_kb_item(name:"Host/OS/icmp", value:os);
   security_note(port:0, data:report);
   exit(0);
  }

   
 }
 if ("IBM Gigabit Ethernet Switch Module" >< os )
 {
   os = "IBM Gigabit Ethernet Switch Module";
   report = "The remote host is running " + os;
   set_kb_item(name:"Host/OS/icmp", value:os);
   security_note(port:0, data:report);
   exit(0);
 }
 if ( "IOS (tm)" >< os )
 {
  version = ereg_replace(pattern:".*IOS.*Version ([0-9]*\.[0-9]*)\(.*",
			 string:egrep(pattern:"IOS", string:os),
			 replace:"\1");

  if ( version != os )
  {
   os = "CISCO IOS " + version;
   report = "The remote host is running " + os;
   set_kb_item(name:"Host/OS/icmp", value:os);
   security_note(port:0, data:report);
   exit(0);
  }
 }

 if ("Digital UNIX" >< os )
 {
  version = ereg_replace(pattern:".*Digital UNIX V([0-9]\.[0-9]).*",
			 string:egrep(pattern:"Digital UNIX", string:os),
			 replace:"\1");
  if ( version != os )
  {
   os = "Digital Unix " + version;
   report = "The remote host is running " + os;
   set_kb_item(name:"Host/OS/icmp", value:os);
   security_note(port:0, data:report);
   exit(0);
  }
 }


 if ("ULTRIX" >< os )
 {
  version = ereg_replace(pattern:".*ULTRIX V([^ ]*).*", 
			 string:egrep(pattern:"ULTRIX", string:os), 
			 replace:"\1");
  if ( version != os ) 
  {
   os = "ULTRIX " + version;
   report = "The remote host is running " + os;
   set_kb_item(name:"Host/OS/icmp", value:os);
   security_note(port:0, data:report);
   exit(0);
  }
 }
 if ("HP-UX" >< os )
 {
   version = ereg_replace(pattern:".*HP-UX [^ ]* ([^ ]*) .*", 
			  replace:"\1", 
			  string:egrep(pattern:"HP-UX", string:os)
			 );
   if ( version != os )
   {
   report = "The remote host is running HP/UX " + version;
   set_kb_item(name:"Host/OS/icmp", value:"HP/UX " + version);
   security_note(port:0, data:report);
   exit(0);
   }
 }

 if ( "kernel 2." >< os )
 {
  version = ereg_replace(pattern:".* kernel (2\.[0-9])\..*", replace:"\1", string:os);
  if ( version != os ) 
  {
  version = "Linux Kernel " + version;
  report = "The remote host is running " + version;
  set_kb_item(name:"Host/OS/icmp", value:version);
  security_note(port:0, data:report);
  exit(0);
  }
 }

 if ("JETDIRECT" >< os )
 {
  version = "HP JetDirect";
  report = "The remote host is running " + version;
  set_kb_item(name:"Host/OS/icmp", value:version);
  security_note(port:0, data:report);
  exit(0);
 } 
 if ("ProCurve Switch" >< os )
 {
  version = "HP ProCurve Switch";
  report = "The remote host is running " + version;
  set_kb_item(name:"Host/OS/icmp", value:version);
  security_note(port:0, data:report);
  exit(0);
 } 

 if ("Xerox" >< os )
 {
  version = "Xerox Printer";
  report = "The remote host is running " + version;
  set_kb_item(name:"Host/OS/icmp", value:version);
  security_note(port:0, data:report);
  exit(0);
 }

 if ("NetQue" >< os )
 {
  report = "The remote host is running NetQue Printer Server";
  set_kb_item(name:"Host/OS/icmp", value:"NetQue Printer Server");
  security_note(port:0, data:report);
  exit(0);
 }

 # http://www.dealtime.co.uk/xPF-Equinox_MDS_10_990410
 if ("EQUINOX MDS" >< os )
 {
  os = "Equinox MDS Transceiver";
  report = "The remote host is running " + os;
  set_kb_item(name:"Host/OS/icmp", value:os);
  security_note(port:0, data:report);
  exit(0);
 }

 if ("Novell NetWare" >< os )
 {
  version = ereg_replace(pattern:".* NetWare ([^ ]*).*", string:os, replace:"\1");
  if ( version != os ) 
  {
  version = split(version, sep:'.', keep:0);
  os = "Novell Netware " + int(version[0]) + "." + int(version[1]) / 10; 
  report = "The remote host is running " + os;
  set_kb_item(name:"Host/OS/icmp", value:os);
  security_note(port:0, data:report);
  exit(0);
  }
 }


 if ("WorkCentre Pro Multifunction System" >< os )
 {
  os = "Xerox WorkCentre Pro"; 
  report = "The remote host is running " + os;
  set_kb_item(name:"Host/OS/icmp", value:os);
  security_note(port:0, data:report);
  exit(0);
 }

 if ("AIX" >< os )
 {
  line = egrep(pattern:"AIX version", string:os);
  version = ereg_replace(pattern:".*AIX version: (.*)$", string:line, replace:"\1");
  if ( version != line )
  {
  version = split(version, sep:'.', keep:0);
  os = "AIX " + int(version[0]) + "." + int(version[1]);
  report = "The remote host is running " + os;
  set_kb_item(name:"Host/OS/icmp", value:os);
  security_note(port:0, data:report);
  exit(0);
  }
 }
}


if ( get_kb_item("Services/rio-karma-upload") ) 
{
 if ( get_port_state(80) )
 {
  soc = open_sock_tcp(80);
  if ( soc )
  {
   send(socket:soc, data:'GET / HTTP/1.0\r\n\r\n');
   r = recv(socket:soc, length:1024);
   close(soc);
   if ( "<title>Welcome to Rio Karma</title>" >< r ) 
	{
        version = split(version, sep:'.', keep:0);
        os = "Rio Karma Embedded Operating System";
  	report = "The remote host is running " + os;
  	set_kb_item(name:"Host/OS/icmp", value:os);
  	security_note(port:0, data:report);
  	exit(0);
	}
  }
 }
}



#
# If NTP is open, try to read data from there. We have to
# normalize the data we get, which is why we don't simply
# spit out 'Host/OS/ntp'
#
os = get_kb_item("Host/OS/ntp");
if ( os )
{
 processor = get_kb_item("Host/processor/ntp");
 # Normalize intel CPUs 
 if ( processor && ereg(pattern:"i[3-9]86", string:processor)) processor = "i386"; 

 if ("QNX" >< os )
 {
  version = str_replace(find:"QNX", replace:"QNX ", string:os);
  report = "The remote host is running " + version;
  set_kb_item(name:"Host/OS/icmp", value:version);
  security_note(port:0, data: report );
  exit(0);
 }
 if ("sparcv9-wrs-vxworks" >< os )
 { 
   version = "VxWorks";
   report = "The remote host is running " + version;
   set_kb_item(name:"Host/OS/icmp", value:version);
   security_note(port:0, data: report );
   exit(0);
 }
 if ( "Darwin" >< os && "Power Macintosh" >< processor )
 {
   if ( "Darwin/" >< os )
     os -= "Darwin/";
   else
     os -= "Darwin";
   num = split(os, sep:".", keep:FALSE);
   version = "Mac OS X 10." + string(int(num[0]) - 4) + "." + num[1];
   report = "The remote host is running " + version;
   set_kb_item(name:"Host/OS/icmp", value:version);
   security_note(port:0, data: report );
   exit(0);
 }
 if ( "Darwin" >< os && "i386" >< processor )
 {
   if ( "Darwin/" >< os )
     os -= "Darwin/";
   else
     os -= "Darwin";
   num = split(os, sep:".", keep:FALSE);
   version = "Mac OS X 10." + string(int(num[0]) - 4) + "." + num[1] + " (intel)";
   report = "The remote host is running " + version;
   set_kb_item(name:"Host/OS/icmp", value:version);
   security_note(port:0, data: report );
   exit(0);
 }

 if ("UNIX/HPUX" >< os )
 {
   report = "The remote host is running HP/UX";
   set_kb_item(name:"Host/OS/icmp", value:"HP/UX");
   security_note(port:0, data: report );
   exit(0);
 }

 if ("NetBSD" >< os )
 {
   os -= "NetBSD";
   version = "NetBSD " + os;
   if ( processor ) version += " (" + processor + ")";

   report = "The remote host is running " + version;
   set_kb_item(name:"Host/OS/icmp", value:version);
   security_note(port:0, data: report );
   exit(0);
 } 

 if ("FreeBSD" >< os )
 {
   os -= "FreeBSD";
   version = "FreeBSD " + os;
   if ( processor ) version += " (" + processor + ")";

   report = "The remote host is running " + version;
   set_kb_item(name:"Host/OS/icmp", value:version);
   security_note(port:0, data: report );
   exit(0);
 }

 if ("OpenBSD" >< os )
 {
   os -= "OpenBSD";
   version = "OpenBSD" + os;
   if ( processor ) version += " (" + processor + ")";

   report = "The remote host is running " + version;
   set_kb_item(name:"Host/OS/icmp", value:version);
   security_note(port:0, data: report );
   exit(0);
 }

 if ("Linux" >< os )
 {
   if ("Linux/" >< os ) os -= "Linux/";
   else os -= "Linux";
   os = "Linux Kernel " + os;
   version = os;
   if ( processor ) version += " (" + processor + ")";
   report = "The remote host is running " + version;
   set_kb_item(name:"Host/OS/icmp", value:version);
   security_note(port:0, data: report );
   exit(0);
 }

 if ("SunOS5." >< os )
 {
  os -= "SunOS5.";
  if ( int(os) >= 7 ) os = "Sun Solaris " + os;
  else os = "Sun Solaris 2." + os;
  version = os;
  if ( processor ) version += " (" + processor + ")";
  report = "The remote host is running " + version;
  set_kb_item(name:"Host/OS/icmp", value:version);
  security_note(port:0, data: report );
   exit(0);
 }

}


ttl = 0; # global
ip_id_sent = "1"; # global
MAX_RETRIES = 3;

db = "
3Com CoreBuilder 3500 Switch:1:1:0:64:0:64:1:0:64:1:0:64:1:8:64:0:1:0:0:1:1:1:0:1:64:4096:M:N:N:N
3Com SuperStack II:1:1:0:255:0:255:1:0:255:1:0:255:1:8:255:0:1:1:1:1:1:1:0:1:255:1024:M:N:N:N
3Com SuperStack II:1:1:0:32:1:32:1:0:32:1:0:32:1:>64:32:0:1:1:1:1:1:1:0:1:32:2048:M:N:N:N
3Com SuperStack switch:1:1:0:255:0:255:1:0:255:1:0:255:1:8:255:0:1:1:2:1:1:1:0:1:255:1024:M:N:N:N
3Com Total Control 1000 Access Server:1:1:0:255:0:255:1:1:255:1:0:255:1:8:255:0:1:2:2:1:1:1:0:1:255:1024:M:N:N:N
6624M TigerSwitch 10/100:1:1:0:64:1:64:1:0:64:1:0:64:1:8:64:0:1:0:0:3:1:3:0:1:64:8192:MNW:0:N:N
A/UX 3.11:1:1:1:255:1:255:1:1:255:1:1:255:1:8:255:1:1:0:0:1:1:1:0:1:32:4096:M:N:N:N
A4/600 Label Printer:1:1:0:32:1:32:1:0:32:1:0:32:1:8:32:0:1:1:2:1:1:1:0:1:32:8192:M:N:N:N
AIX 4.0/4.2:1:1:1:255:1:255:1:0:255:1:1:255:1:8:255:1:1:1:2:1:>20:1:0:1:64:16060:M:N:N:N
AIX 4.0:1:1:1:255:1:255:1:0:255:1:0:255:1:8:255:1:1:0:2:1:>20:1:1:1:64:16060:M:N:N:N
AIX 4.0:1:1:1:255:1:255:1:0:255:1:1:255:1:8:255:1:1:0:2:3:>20:1:1:1:64:64240:M:N:N:N
AIX 4.0:1:1:1:255:1:255:1:0:255:1:1:255:1:8:255:1:1:0:2:3:>20:1:1:1:64:65535:MNWNNT:2:1:1
AIX 4.1:1:1:1:255:1:255:1:0:255:1:1:255:1:8:255:1:1:0:2:1:>20:1:1:1:64:15400:M:N:N:N
AIX 4.1:1:1:1:255:1:255:1:0:255:1:1:255:1:8:255:1:1:0:2:1:>20:1:1:1:64:64240:M:N:N:N
AIX 4.2:1:1:1:255:1:255:1:0:255:1:1:255:1:8:255:1:1:1:2:1:>20:1:0:1:64:16340:M:N:N:N 
AIX 4.3:1:1:1:255:0:255:1:0:255:1:1:255:1:8:255:1:1:0:2:1:>20:1:1:1:64:16060:M:N:N:N
AIX 4.3:1:1:1:255:1:255:1:0:255:1:1:255:1:8:255:1:1:0:2:1:>20:1:0:1:64:16060:M:N:N:N
AIX 4.3:1:1:1:255:1:255:1:0:255:1:1:255:1:8:255:1:1:0:2:1:>20:1:1:1:64:16060:M:N:N:N 
AIX 5.1:1:1:1:255:1:255:1:0:255:1:1:255:1:8:255:1:1:0:2:1:>20:1:0:1:64:51100:M:N:N:N
AIX 5.1:1:1:1:255:1:255:1:0:255:1:1:255:1:8:255:1:1:0:2:1:>20:1:0:1:64:16384:M:N:N:N
AIX 5.1:1:1:1:255:1:255:1:0:255:1:1:255:1:8:255:1:1:0:2:1:>20:1:0:1:64:65160:MNWNNT:0:1:1
AIX 5.1:1:1:1:255:1:255:1:0:255:1:1:255:1:8:255:1:1:0:2:1:>20:1:0:1:64:65535:M:N:N:N
AIX 5.1:0:1:1:255:1:255:1:0:255:1:1:255:1:8:255:1:1:0:2:1:>20:1:0:1:64:16560:M:N:N:N
AIX 5.1:1:1:1:255:1:255:1:0:255:1:1:255:1:8:255:1:1:0:2:1:>20:1:0:1:64:65535:MNWNNT:4:1:1
AIX 5.1:1:1:1:255:1:255:1:0:255:1:1:255:1:8:255:1:1:0:2:1:>20:1:1:1:64:17520:M:N:N:N
AIX 5.1:1:1:1:255:1:255:1:0:255:1:1:255:1:8:255:1:1:0:2:1:>20:1:1:1:64:65535:MNWNNTNNS:4:1:1
AIX 5.2:1:1:1:255:1:255:1:0:255:1:1:255:1:8:255:1:1:0:2:1:>20:1:0:1:64:17376:MNWNNT:0:1:1
AIX 5.2:0:1:1:255:1:255:1:0:255:1:1:255:1:8:255:1:1:0:2:1:>20:1:1:1:64:16560:M:N:N:N
AIX 5.2:1:1:1:255:1:255:1:0:255:1:1:255:1:8:255:1:1:0:2:1:>20:1:0:1:64:17520:M:N:N:N
AIX 5.2:1:1:1:255:1:255:1:0:255:1:1:255:1:8:255:1:1:0:2:1:>20:1:1:1:64:65535:M:N:N:N
AIX 5.3:1:1:1:255:1:255:1:0:255:1:1:255:1:8:255:1:1:0:2:3:>20:1:1:1:64:17520:M:N:N:N
APC PowerNet UPS:0:1:0:64:1:64:1:0:64:1:1:64:1:8:64:0:1:2:1:1:1:1:0:1:64:1600:M:N:N:N 
APC PowerNet UPS:1:1:0:255:0:255:1:0:255:1:0:255:1:8:255:0:1:1:1:1:1:1:1:1:64:4344:MNWNNSNNT:0:1:1   
APC PowerNet UPS:1:1:0:255:0:255:1:0:255:1:0:255:1:8:255:0:1:1:1:1:1:1:1:1:64:4344:MNWNNT:0:1:1
APC UPS Management Card:1:1:0:255:0:255:1:0:255:1:0:255:1:8:255:0:1:1:2:1:1:1:1:1:64:4344:MNWNNT:0:1:1
Actiontec GT701 DLS Modem:1:1:0:255:1:255:1:0:255:1:0:255:1:64:255:0:1:2:2:3:>20:1:1:0:64:5792:MSTNW:0:1:1
Adtran ATLAS 550:0:1:0:64:0:64:1:1:64:1:0:64:1:8:64:0:1:1:2:1:1:1:0:1:64:4096:M:N:N:N
Alcatel Speed Touch Pro:1:1:1:255:1:255:1:1:255:1:0:255:1:8:255:1:1:1:0:1:1:1:0:1:64:4096:MNWNNT:0:1:1
Alcatel Speed Touch:1:1:0:64:1:64:1:1:64:1:0:64:1:8:64:0:1:1:2:1:1:1:0:1:64:4096:MNWNNT:0:1:1
Allied Telesyn AR320 Router:0:S:1:64:1:64:S:1:64:S:0:64:S:8:255:0:1:1:1:1:1:1:0:1:64:1024:M:N:N:N
Allot NetEnforcer:1:1:0:255:1:255:1:0:255:1:0:255:1:>64:255:0:1:1:1:1:1:1:1:1:64:1360:MSTNW:0:1:1
AltaVista Tunnel Server:1:1:1:64:0:64:1:0:64:1:0:64:1:8:64:1:1:0:1:1:1:1:1:1:64:33580:MNW:0:N:N
Alteon:1:1:0:255:0:255:1:0:255:1:0:255:1:8:255:0:1:1:1:1:1:1:0:1:255:4096:M:N:N:N
Alteon:1:1:0:255:0:255:1:0:255:1:0:255:1:8:255:0:1:1:1:1:1:1:0:1:255:8760:M:N:N:N
Ascend Max-HP Modem Hub:1:1:0:255:0:255:1:0:255:1:0:255:1:8:64:0:1:1:2:1:1:1:0:1:64:4380:M:N:N:N
Ascend Pipeline Router:1:1:0:255:0:255:1:0:255:1:0:255:1:8:64:0:1:1:2:1:1:1:0:1:64:4380:M:N:N:N
Askey Ethernet Switch:1:1:1:64:1:64:1:0:64:1:0:64:1:8:64:1:1:0:0:1:1:1:1:1:64:8192:MNWNNT:0:1:1
AsyncOS:1:1:1:64:1:64:1:0:64:1:0:64:1:8:64:1:1:0:1:3:1:1:1:1:64:16384:MNWNNT:0:1:1
Avaya VPNet VSU 2000::1:1:1:255:1:255:1:0:255:1:0:255:1:8:255:1:1:0:0:3:>20:3:0:1:64:4380:M:N:N:N
Axis Network Camera:1:1:0:64:1:64:1:0:64:1:0:64:1:>64:64:0:1:1:2:1:1:1:0:1:64:16352:M:N:N:N
Axis Network Camera:1:1:0:64:1:64:1:0:64:1:0:64:1:>64:64:0:1:1:2:1:1:1:0:1:64:32736:M:N:N:N
BSDI BSD/OS 4.0:1:1:1:255:1:255:1:0:255:1:0:255:1:8:255:1:1:2:2:1:>20:1:1:1:64:8280:MNWNNT:0:1:1
BUG inc. IP stack:0:1:0:64:0:64:1:0:64:1:0:64:1:8:64:0:1:1:1:1:1:1:0:1:64:8192:M:N:N:N
Belkin Wireless Router:1:1:1:64:1:64:1:0:64:1:0:64:1:X:X:X:X:X:X:X:X:X:0:1:64:8192:MNW:0:N:N
Bintec Router:1:1:1:64:0:64:1:0:64:1:0:64:1:8:64:0:1:1:2:3:1:3:0:1:64:4096:M:N:N:N
Bintec VPN Access:1:1:1:64:0:64:1:0:64:1:0:64:1:8:64:0:1:1:2:3:1:3:0:1:64:16384:M:N:N:N
BlueCoat SG400:1:1:1:255:0:255:1:0:255:1:0:255:1:8:255:1:1:0:0:3:>20:3:0:1:64:65535:MNWNNT:0:1:1
BreezeAccess SU-I Local Loop Radio:1:1:0:64:0:64:1:0:64:1:0:64:1:8:64:1:1:1:1:1:1:1:1:1:64:1500::N:N:N
Bytecc LanDisk:1:1:0:32:0:32:1:1:32:1:0:32:1:8:32:0:1:1:2:1:1:1:0:1:32:65535:M:N:N:N
CISCO ATA:1:1:0:255:0:255:1:0:255:1:0:255:1:8:255:0:1:1:1:1:1:1:0:1:255:16000:M:N:N:N
CISCO CatOS 8.3:1:1:1:64:1:64:1:1:64:1:1:64:1:8:64:1:1:0:0:1:1:1:0:1:255:4096:M:N:N:N
CISCO Catalyst 5000:1:1:1:64:1:64:1:1:64:1:1:64:1:8:64:1:1:0:0:1:1:1:0:1:32:4096::N:N:N
CISCO Catalyst:1:1:1:64:1:64:1:1:64:1:1:64:1:8:64:1:1:0:0:1:1:1:0:1:32:4096:M:N:N:N
CISCO Content Switch:0:1:0:128:0:128:1:1:128:1:0:128:1:8:64:1:1:0:2:1:1:1:0:1:64:8192:M:N:N:N
CISCO Content Switch:1:1:0:255:1:255:1:0:255:1:0:255:1:>64:255:0:1:1:2:1:1:1:0:1:64:5840:MNNS:N:N:N
CISCO IOS 11.2:1:S:1:255:1:255:S:0:255:S:1:255:S:8:255:0:1:1:1:1:1:1:0:0:255:4288:M:N:N:N
CISCO IOS 11.2:1:S:1:255:1:255:S:0:255:S:1:255:S:8:255:0:1:1:2:1:1:1:0:0:255:4288:M:N:N:N
CISCO IOS 12.0:1:S:1:255:0:255:1:0:255:1:0:255:1:8:255:0:1:2:1:1:1:1:0:0:255:4128:M:N:N:N
CISCO IOS 12.0:1:S:1:255:0:255:1:0:255:1:1:255:S:8:255:0:1:1:2:1:1:1:0:0:255:4128:MS:N:N:N
CISCO IOS 12.0:1:S:1:255:1:255:S:0:255:S:0:255:S:8:255:0:1:1:1:1:1:1:0:0:255:4128:M:N:N:N
CISCO IOS 12.0:1:S:1:255:1:255:S:0:255:S:1:255:S:8:255:0:1:1:1:1:1:1:0:0:255:4128:M:N:N:N
CISCO IOS 12.1:1:S:1:255:1:255:S:0:255:S:1:255:S:8:255:0:1:1:2:1:1:1:0:0:255:4128:M:N:N:N
CISCO IOS 12.2:1:S:1:255:0:255:1:0:255:1:0:255:1:8:255:0:1:2:2:1:1:1:0:0:255:4128:M:N:N:N
CISCO IOS 12.2:1:S:1:255:1:255:S:0:255:S:0:255:S:8:255:0:1:1:2:1:1:1:0:0:255:4128:M:N:N:N
CISCO IOS 12.2:1:S:1:255:1:255:S:0:255:S:1:255:S:8:255:0:1:1:1:1:1:1:0:0:255:1460:M:N:N:N
CISCO IOS 12.2:1:S:1:255:1:255:S:0:255:S:1:255:S:8:255:0:1:1:2:1:1:1:0:0:255:4288
CISCO IOS 12.3:1:1:1:255:1:255:1:0:255:1:0:255:1:8:255:0:1:1:1:3:1:1:0:0:255:4128:M:N:N:N
CISCO IOS 12.3:1:S:1:255:0:255:1:0:255:1:0:255:1:8:255:0:1:1:1:1:1:1:0:0:255:4128:M:N:N:N
CISCO IOS 12.3:1:S:1:255:1:255:S:0:255:S:0:255:S:8:255:0:1:1:1:1:1:1:0:0:255:4128:M:N:N:N
CISCO IOS 12.3:0:S:1:255:1:255:S:0:255:S:0:255:S:8:255:0:1:1:2:1:1:1:0:0:255:4128:M:N:N:N
CISCO IP Telephone 7940:1:1:0:64:0:64:1:0:64:1:0:64:1:8:64:0:1:1:1:1:1:1:0:1:64:1400:M:N:N:N
CISCO IP Telephone 7940:1:1:0:64:0:64:1:0:64:1:0:64:1:8:64:0:1:1:2:1:1:1:0:1:64:1400:M:N:N:N
CISCO Local Director 4.2:1:1:1:64:0:64:1:0:64:1:0:64:1:X:X:X:X:X:X:X:X:X:X:0:1:255:4096:M:N:N:N
CISCO VPN Concentrator:1:S:1:128:0:128:1:0:128:1:0:128:1:8:128:0:0:1:1:1:1:1:1:S:128:5840::N:N:N
CISCO VPN Concentrator:1:S:1:128:0:128:1:0:128:1:0:128:1:8:128:0:0:1:2:1:1:1:0:1:128:8192:MNWNNT:0:1:1
CISCO VPN Concentrator:1:S:1:128:0:128:1:1:255:S:0:255:S:8:128:0:0:1:2:1:1:1:0:1:128:8192:MNWNNT:0:1:1
Cabletron Switch:1:1:0:255:0:255:1:0:255:1:0:255:1:8:255:0:1:1:2:1:1:1:0:1:255:536:M:N:N:N
Cabletron Switch:1:1:0:32:0:32:1:1:32:1:0:32:1:8:255:1:S:0:1:1:1:1:0:0:32:4096::N:N:N
Canon Digital Copier (iR4570):1:1:1:64:1:64:1:0:64:1:0:64:1:8:64:1:1:0:0:1:1:1:1:1:64:16384:MNWNNT:0:1:1
Cayman DSL Router:1:1:0:32:0:32:1:0:32:1:0:32:1:8:255:0:1:1:1:1:1:1:0:1:32:4096::N:N:N
CheckPoint Secure Platform NGX:1:1:0:255:0:255:1:0:255:1:0:255:1:>64:255:0:1:1:2:1:1:1:1:0:64:5840:MNNSNW:0:N:N
Cyclades Terminal Server:1:1:0:255:0:255:1:0:255:1:0:255:1:>64:255:0:1:1:1:3:1:1:1:0:64:5792:MSTNW:0:1:1
D-Link DI-604 Router:1:1:0:64:0:64:1:0:64:1:0:64:1:8:64:0:1:1:1:1:1:1:0:1:64:5840:MS:N:N:N
D-Link DI-614+ WLAN Access Point:1:1:0:128:1:128:1:0:128:1:0:128:1:8:128:0:1:1:1:1:1:1:0:1:128:8192:MW:0:N:N
D-Link DI-624 WLAN Access Point:1:1:0:128:1:128:1:0:128:1:0:128:1:8:128:0:1:1:1:1:1:1:0:1:128:8192:M:N:N:N
D-Link DI-624+ WLAN Access Point:1:1:0:128:1:128:1:0:128:1:0:128:1:8:128:0:1:1:1:1:1:1:0:1:128:8192:M:N:N:N
D-Link DI-713P WLAN Access Point:1:1:0:64:0:64:1:0:64:1:0:64:1:8:64:0:1:1:1:1:1:1:0:1:64:5840:M:N:N:N
D-Link Router:1:1:0:128:1:128:1:0:128:1:0:128:1:8:128:0:1:1:1:1:1:1:0:1:128:8192:M:N:N:N
D-Link Router:1:1:0:128:1:128:1:0:128:1:0:128:1:8:128:0:1:1:2:1:1:1:0:1:128:8192:M:N:N:N
D-Link Router:1:1:0:64:0:64:1:0:64:1:0:64:1:8:64:0:1:1:1:1:1:1:0:1:64:5808:M:N:N:N
D-Link WLAN Access Point:1:1:0:128:1:128:1:0:128:1:0:128:1:8:128:0:1:1:2:1:1:1:0:1:128:8192:M:N:N:N
D-Link WLAN Access Point:1:1:0:128:1:128:1:0:128:1:0:128:1:8:128:0:1:2:2:1:1:1:0:1:128:8192:M:N:N:N
D-Link WLAN Access Point:1:1:0:32:0:32:1:0:32:1:0:32:1:X:X:X:X:X:X:X:X:X:0:1:32:16000:M:N:N:N
Dell Advocent KVM:1:0:1:255:1:255:0:0:255:0:0:255:0:>64:255:1:0:1:2:1:1:1:1:0:64:5792:MSTNW:0:1:1
Dell Laser Printer:1:1:1:255:1:255:1:1:255:1:1:255:1:8:255:1:1:1:0:1:>20:1:0:1:32:12288::N:N:N
Dell PowerConnect Switch:1:1:1:255:1:255:1:0:255:1:0:255:1:8:255:1:1:0:0:1:>20:1:0:1:64:8192:MNWNNT:0:1:1
Dell PowerVault Backup Server:1:1:1:64:1:64:1:0:64:1:0:64:1:8:64:1:1:0:0:3:1:3:0:1:64:1400:MNW:0:N:N
Dell PowerVault:1:1:1:64:1:64:1:0:64:1:0:64:1:8:64:1:1:1:0:3:1:3:0:1:64:8192:MNW:0:N:N
Dell Remote Access Controller:1:1:1:255:1:255:1:1:255:1:1:255:1:8:255:1:1:1:0:1:1:3:0:1:64:4096:MNWN:1:N:N:
Digi PortServer:1:S:0:64:0:64:1:0:64:1:0:64:1:>64:64:1:1:1:2:1:1:1:0:1:64:8192:M:N:N:N
Digital Loggers Ethernet Power Controller:1:1:0:64:0:64:1:0:64:1:0:64:1:8:64:0:1:1:2:1:1:1:0:1:64:0:M:N:N:N:
Digital Unix 4.0:1:1:1:64:1:64:1:0:64:1:1:64:1:8:64:1:1:0:1:1:1:1:1:1:64:33580:MNW:0:N:N
DryStar Printer:0:1:0:255:0:255:1:1:255:1:0:255:1:8:255:0:1:1:1:1:1:1:0:1:64:8760:M:N:N:N
ELSA LANCOM Wireless Router:1:1:0:64:0:64:1:0:64:1:0:64:1:8:64:0:1:1:1:1:1:1:0:1:64:1400::N:N:N
EMC Celerra File Server:1:1:0:255:0:255:1:0:255:1:0:255:1:8:255:0:1:1:2:3:1:3:0:1:64:65535:MNWNNT:3:1:1
Efficient SDSL Router:1:1:1:255:1:255:1:0:255:1:0:255:1:8:255:1:1:0:2:3:>20:1:0:1:64:4096:MM:N:N:N
Enterasys Networks 1H582:1:1:1:64:1:64:1:0:64:1:0:64:1:8:64:1:1:0:0:1:1:1:0:1:64:8192:MNWNNT:0:1:1
Enterasys Networks 6G306:0:1:1:255:1:255:1:1:255:1:0:255:1:8:255:0:1:0:1:1:1:1:0:1:255:4096:M:N:N:N
Enterasys Networks Matrix E5:1:1:1:255:1:255:1:1:255:1:1:255:1:8:255:1:1:1:0:1:1:1:0:1:64:4096::N:N:N
Enterasys Networks Matrix N7:1:1:1:64:1:64:1:0:64:1:0:64:1:8:64:1:1:0:0:1:1:1:0:1:64:8192:MNWNNT:0:1:1
Enterasys Vertical Horizon Switch:1:1:1:255:1:255:1:1:255:1:1:255:1:8:255:1:1:1:0:1:1:1:0:1:64:4096::N:N:N
Enterasys XP 2004 10.0 Switch:1:1:1:255:1:255:1:0:255:1:0:255:1:8:255:1:1:0:2:1:1:1:1:1:64:17376:MNWNNT:0:1:1
Enterasys XSR-1805:1:S:1:255:0:255:1:1:255:S:0:255:S:8:255:0:0:1:1:1:1:1:0:1:255:8192:MNWNNT:0:1:1
Ericson HM220DP ADSL Modem/Router:0:1:1:32:0:32:1:1:32:1:0:32:1:8:32:0:1:0:2:1:1:1:0:1:64:8112:M:N:N:N
Extreme Alpine Switch:1:1:1:128:1:128:1:1:128:1:1:128:1:8:128:1:1:0:2:1:>20:1:0:1:32:4096:M:N:N:N
ExtremeNetwork Switch:1:1:1:128:1:128:1:1:128:1:0:128:1:8:128:1:1:0:2:1:>20:1:0:1:32:4096:M:N:N:N 
F5 Network BIGIP 2400:1:1:1:255:1:255:1:0:255:1:0:255:1:8:255:1:1:1:1:3:1:1:1:1:64:65535:MNWNNT:3:1:1
F5 Networks Appliance:1:1:1:255:0:255:1:0:255:1:0:255:1:8:255:1:1:1:1:3:1:1:1:1:64:17520:MNWNNT:0:1:1
F5 Networks Appliance:1:1:1:255:1:255:1:0:255:1:0:255:1:8:255:1:1:1:2:3:1:1:1:1:64:17520:MNWNNT:0:1:1
F5 Networks BIGIP 2400:1:1:1:255:0:255:1:0:255:1:0:255:1:8:255:1:1:1:1:3:1:1:1:0:64:5792:MSTNW:0:1:1
Fabric OS:1:1:1:255:1:255:1:1:255:1:1:255:1:8:255:1:1:0:0:3:1:3:0:1:32:4096:M:N:N:N
Fluke OptiView:1:1:0:255:0:255:1:0:255:1:0:255:1:8:255:0:1:1:2:1:1:1:0:1:255:16384:M:N:N:N
Fluke Optiview Network Analyzer:1:1:0:255:0:255:1:0:255:1:0:255:1:8:255:0:1:1:2:1:1:1:1:1:128:14600:MNWNNTNNS:0:0:0
Foundry Networks Load Balancer:1:1:0:64:0:64:1:0:64:1:0:64:1:64:64:0:1:1:1:1:1:1:0:1:64:16384:M:N:N:N
Foundry Networks Load Balancer:1:1:0:64:0:64:1:0:64:1:0:64:1:8:64:0:1:2:1:1:1:1:0:1:64:16384:M:N:N:N
FreeBSD 3.3:1:1:1:255:1:255:1:0:255:1:0:255:1:8:255:1:1:0:2:3:1:3:1:1:64:17520:M:N:N:N
FreeBSD 3.4:1:1:1:255:1:255:1:0:255:1:0:255:1:8:255:1:1:0:2:3:1:3:1:1:64:17520:M:N:N:N
FreeBSD 3.5:1:1:1:255:1:255:1:0:255:1:0:255:1:8:255:1:1:0:2:3:1:3:1:1:64:17520:M:N:N:N
FreeBSD 4.0:1:1:1:255:1:255:1:0:255:1:0:255:1:8:255:1:1:0:2:3:1:3:1:1:64:17520:M:N:N:N
FreeBSD 4.10:1:1:1:64:0:64:1:0:64:1:0:64:1:8:64:1:1:2:2:1:1:1:1:1:64:57344:MNWNNT:0:1:1
FreeBSD 4.1:1:1:1:255:1:255:1:0:255:1:0:255:1:8:255:1:1:0:2:3:1:3:1:1:64:17520:M:N:N:N
FreeBSD 4.2:1:1:1:255:1:255:1:0:255:1:0:255:1:8:255:1:1:0:1:1:1:1:1:1:64:17520:M:N:N:N
FreeBSD 4.3:1:1:1:255:1:255:1:0:255:1:0:255:1:8:255:1:1:0:2:3:1:3:1:1:64:4380:M:N:N
FreeBSD 4.3:1:1:1:255:1:255:1:0:255:1:0:255:1:8:255:1:1:0:2:3:1:3:1:1:64:65535:MNWNNT:1:1:1
FreeBSD 4.4:1:1:1:64:1:64:1:0:64:1:0:64:1:8:64:1:1:0:1:1:1:1:1:1:64:17376:MNWNNT:0:1:1
FreeBSD 4.5:1:1:1:64:1:64:1:0:64:1:0:64:1:8:64:1:1:0:1:1:1:1:0:1:64:65535:MNWNNT:1:1:1
FreeBSD 4.6:1:1:1:64:1:64:1:0:64:1:0:64:1:8:64:1:1:0:1:1:1:1:0:1:64:57344:MNWNNT:0:1:1
FreeBSD 4.7:1:1:1:64:1:64:1:0:64:1:0:64:1:8:64:1:1:0:1:1:1:1:1:1:64:57344:MNWNNT:0:1:1
FreeBSD 4.8:1:1:1:64:1:64:1:0:64:1:0:64:1:8:64:1:1:0:1:1:1:1:1:1:64:57344:MNWNNT:0:1:1
FreeBSD 4.9:1:1:1:64:0:64:1:0:64:1:0:64:1:8:64:1:1:0:2:1:1:1:1:1:64:57344:MNWNNT:0:1:1
FreeBSD 4.9:1:1:1:64:1:64:1:0:64:1:0:64:1:8:64:1:1:0:1:1:1:1:1:1:64:57344:MNWNNT:0:1:1
FreeBSD 4.9:1:1:1:64:1:64:1:0:64:1:0:64:1:8:64:1:1:0:1:1:1:1:1:1:64:65535:MNWNNT:0:1:1
FreeBSD 4.9:1:1:1:64:1:64:1:0:64:1:0:64:1:8:64:1:1:0:2:1:1:1:1:1:64:57344:MNWNNT:0:1:1
FreeBSD 5.1:1:1:1:64:1:64:1:0:64:1:0:64:1:8:64:1:1:0:1:1:1:1:1:1:64:65535:MNWNNT:1:1:1
FreeBSD 5.1:1:1:1:64:1:64:1:0:64:1:0:64:1:8:64:1:1:0:1:1:1:1:1:1:64:65535:MNWNNTNNS:1:1:1
FreeBSD 5.2:1:1:0:64:0:64:1:0:64:1:0:64:1:8:64:0:1:1:2:3:1:3:0:1:64:65535:MNWNNT:1:1:1
FreeBSD 5.2:1:1:1:64:0:64:1:0:64:1:0:64:1:8:64:1:1:0:1:1:1:1:1:1:64:65535:MNWNNT:1:1:1
FreeBSD 5.3:1:1:1:64:1:64:1:0:64:1:0:64:1:8:64:1:1:0:2:1:1:1:1:1:64:65535:MNWNNTNNS:1:1:1
FreeBSD 6.0:1:1:1:128:1:128:1:0:128:1:0:128:1:8:128:1:1:0:2:1:1:1:1:1:128:65535:MNWNNTS:1:1:1
FreeBSD 6.0:1:1:1:64:0:64:1:0:64:1:0:64:1:8:64:1:1:2:2:1:1:1:1:1:64:65535:MNWNNTS:1:1:1
GNET Wireless Access Point:1:1:0:255:0:255:1:0:255:1:0:255:1:8:255:0:1:1:1:1:1:1:0:1:255:5840:MS:N:N:N
Google Mini Search Appliance:1:1:0:255:1:255:1:0:255:1:0:255:1:>64:255:0:1:1:2:1:1:1:1:1:64:30660:MSTNW:0:1:1
GrandStream HandyTone VOIP Adapter:0:1:0:255:0:255:1:0:255:1:0:255:1:8:255:0:1:1:2:1:1:1:1:1:255:1446:M:N:N:N
HP 3000 - MPE/iX:1:S:0:255:1:255:S:1:255:S:1:255:S:8:255:0:0:1:2:1:1:1:0:1:255:12020:M:N:N:N
HP AdvanceStack Switch:1:1:1:32:1:32:1:0:32:1:0:1:8:32:0:1:1:2:1:1:1:0:1:32:1024:M:N:N:N
HP Deskjet 6127:1:1:0:255:0:255:1:0:255:1:0:255:1:8:255:0:1:1:2:1:1:1:1:1:64:2896:MNWNNSNNT:0:1:1
HP IP Console Switch:1:0:1:255:1:255:0:0:255:0:0:255:0:>64:255:1:0:1:1:1:1:1:1:0:64:5792:MSTNW:0:1:1
HP Integrated Lights Out Board:1:1:0:64:0:64:1:0:64:1:0:64:1:8:64:0:1:1:1:1:1:1:0:1:64:5840:M:N:N:N
HP Integrated Lights Out Board:1:1:0:64:0:64:1:0:64:1:0:64:1:8:64:0:1:1:1:1:1:1:0:1:64:5840:MS:N:N:N
HP Integrated Lights Out Board:1:1:0:64:0:64:1:0:64:1:0:64:1:8:64:0:1:1:2:1:1:1:0:1:64:5840:M:N:N:N
HP Integrated Lights Out Board:1:1:0:64:0:64:1:0:64:1:0:64:1:8:64:0:1:1:2:1:1:1:0:1:64:5840:MS:N:N:N
HP Integrated Lights Out Board:1:1:1:64:1:64:1:0:64:1:0:64:1:8:64:1:1:0:0:1:1:1:0:1:64:8192:MNWNNT:0:1:1
HP JetDirect:0:1:0:64:0:64:1:0:64:1:0:64:1:8:64:0:1:1:0:1:1:1:0:1:64:2144:M:N:N:N
HP JetDirect:0:1:0:64:0:64:1:0:64:1:0:64:1:8:64:0:1:1:1:1:1:1:0:1:64:2144:M:N:N:N 
HP JetDirect:0:1:0:64:0:64:1:0:64:1:0:64:1:8:64:0:1:1:1:1:1:1:0:1:64:5840:M:N:N:N
HP JetDirect:0:1:0:64:0:64:1:0:64:1:0:64:1:8:64:0:1:1:1:3:1:1:0:1:64:5840:M:N:N:N
HP JetDirect:0:1:0:64:0:64:1:0:64:1:0:64:1:8:64:0:1:1:2:1:1:1:0:1:64:5840:M:N:N:N
HP JetDirect:1:0:1:255:1:255:0:0:255:0:0:255:0:>64:255:1:0:1:2:1:1:1:1:0:255:1448:MSTNW:0:1:1
HP JetDirect:1:1:1:64:0:64:1:0:64:1:0:64:1:8:64:1:1:0:0:3:1:3:0:1:64:1460:MNWNNT:0:1:1 
HP JetDirect:1:1:1:64:0:64:1:0:64:1:0:64:1:8:64:1:1:0:0:3:1:3:0:1:64:8192:MNW:0:N:N
HP JetDirect:1:1:1:64:1:64:1:0:64:1:0:64:1:8:64:1:1:0:0:3:1:3:0:1:64:1460:MNW:0:N:N
HP JetDirect:1:1:1:64:1:64:1:0:64:1:0:64:1:8:64:1:1:0:0:3:1:3:0:1:64:1460:MNWNNT:0:1:1
HP JetDirect:1:1:1:64:1:64:1:0:64:1:0:64:1:8:64:1:1:0:0:3:1:3:0:1:64:5840:MNW:0:N:N
HP JetDirect:1:1:1:64:1:64:1:0:64:1:0:64:1:8:64:1:1:0:0:3:1:3:0:1:64:5840:MNWNNT:0:1:1
HP JetDirect:1:1:1:64:1:64:1:0:64:1:0:64:1:8:64:1:1:0:0:3:1:3:0:1:64:8192:MNW:0:N:N
HP JetDirect:1:S:0:255:1:255:S:1:255:S:1:255:S:8:255:0:0:1:1:1:1:1:0:1:255:24576:M:N:N:N
HP LaserJet 4200:1:1:1:64:0:64:1:0:64:1:0:64:1:8:64:1:1:0:0:3:1:3:0:1:64:5840:MNWNNT:0:1:1
HP LaserJet:0:1:1:255:1:255:1:1:255:1:0:255:1:64:255:1:1:1:2:1:1:1:1:1:255:10136:NNTNWM:0:1:1
HP P1218A TopTools Remote Control:1:1:1:255:1:255:1:1:255:1:1:255:1:8:255:1:1:1:0:1:1:3:0:1:64:4096::N:N:N 
HP ProCurve Switch:1:1:0:64:1:64:1:0:64:1:0:64:1:8:64:0:1:0:0:1:1:3:0:1:64:8192:MNW:0:N:N
HP ProCurve Switch:1:1:1:64:1:64:1:1:64:1:1:64:1:8:64:1:1:0:0:3:1:3:0:1:64:4096:M:N:N:N
HP/UX 10.20:1:1:1:255:1:255:1:0:255:1:1:255:1:8:255:1:1:1:0:1:1:1:1:1:64:32768:M:N:N:N
HP/UX B.11.0:1:1:1:255:0:255:1:1:255:1:0:255:1:64:255:1:1:1:1:1:1:1:1:1:64:32768:MNNSWNNNT:0:1:1
HP/UX B.11.11:1:1:1:255:0:255:1:0:255:1:0:255:1:64:255:0:1:1:1:1:1:1:0:1:64:32768:MNNSWNNNT:0:1:1 
HP/UX B.11.11:1:1:1:255:0:255:1:0:255:1:0:255:1:64:255:1:1:1:1:1:1:1:1:1:64:32768:MNNSWNNNT:0:1:1
HP/UX B.11.11:1:1:1:255:0:255:1:0:255:1:0:255:1:64:255:1:1:1:2:1:1:1:1:1:64:32768:MNNSWNNNT:0:1:1
IBM 4690 OS version 3:1:1:1:255:1:255:1:1:255:1:1:255:1:8:255:1:1:0:0:3:1:3:0:1:32:28672:M:N:N:N
IBM Gigabit Switch Module:1:S:1:32:0:32:1:0:32:1:0:32:1:8:32:0:0:1:1:1:1:1:0:1:32:8192:MNWNNT:0:1:1
IBM OS/390:0:1:0:32:0:32:1:0:32:1:0:32:1:8:32:0:1:1:1:1:1:1:0:1:32:65535:MNWNNT:4:1:1
IBM OS/390:1:1:0:64:1:64:1:0:64:1:0:64:1:8:64:0:1:1:1:1:1:1:0:1:64:32768:MNNT:N:1:1
IBM OS/390:1:1:0:64:1:64:1:0:64:1:0:64:1:8:64:0:1:1:2:1:1:1:0:1:64:32768:MNNT:N:1:1
IBM OS/390:1:1:1:64:1:64:1:0:64:1:0:64:1:8:64:0:1:1:1:1:1:1:0:1:64:32768:M:N:N:N
IBM OS/390:1:1:1:64:1:64:1:0:64:1:0:64:1:8:64:0:1:1:2:1:1:1:0:1:64:32768:M:N:N:N
IBM OS/400:1:1:0:64:1:64:1:0:64:1:0:64:1:8:64:0:1:1:1:1:1:1:1:1:64:8192:MNWNNT:0:1:1
IBM OS/400:1:1:0:64:1:64:1:0:64:1:0:64:1:8:64:0:1:1:2:1:1:1:0:1:64:8192:MNWNNT:0:1:1
IBM OS/400:1:1:0:64:1:64:1:0:64:1:0:64:1:8:64:0:1:1:2:1:1:1:1:1:64:32768:MNWNNT:5:1:1
IBM OS/400:1:1:0:64:1:64:1:0:64:1:0:64:1:8:64:0:1:1:2:1:1:1:1:1:64:64384:MNWNNT:0:1:1
IPCop (Linux Kernel 2.4 firewall):1:1:0:64:1:64:1:0:64:1:0:64:1:>64:64:0:1:1:1:1:1:1:1:0:64:5840:M:N:N:N
IRIX 5.3:1:1:1:255:1:255:1:1:255:1:1:255:1:8:255:1:1:1:2:1:1:1:0:1:64:60816:MNWNNT:0:1:1
IRIX 6.5:1:1:1:255:1:255:1:0:255:1:0:255:1:8:255:1:1:1:1:1:1:1:1:1:64:60816:MNWNNTNNS:0:1:1
IRIX 6.5:1:1:1:255:1:255:1:0:255:1:0:255:1:8:255:1:1:1:2:1:1:1:1:1:64:60816:MNWNNTNNS:0:1:1
IRIX 6.5:1:1:1:255:1:255:1:1:255:1:0:255:1:8:255:1:1:1:1:1:1:1:1:1:64:60816:MNWNNTNNS:0:1:1
Infotec Multifunction Copier:1:1:1:255:1:255:1:0:255:1:0:255:1:8:255:1:1:0:0:1:1:1:0:1:64:16384:MNWNNT:0:1:1
Intel NetportExpress Print Station:1:1:0:255:0:255:1:0:255:1:0:255:1:8:255:0:1:0:0:1:1:1:0:1:255:5840:M:N:N:N
JVC VN-C1U Webcam:1:1:0:64:1:64:1:1:64:1:0:64:1:8:64:0:1:1:1:3:1:1:0:1:64:4728:M:N:N:N
Juniper CMTS:1:0:1:255:1:255:0:0:255:0:0:255:0:>64:255:1:1:1:2:1:1:1:1:0:64:5792:MSTNW:0:1:1
Juniper M7i:1:1:1:255:0:255:1:0:255:1:0:255:1:8:255:1:1:2:2:1:1:1:0:1:64:16500:MNWNNT:0:1:1
Juniper M7i:1:1:1:255:1:255:1:0:255:1:0:255:1:8:255:1:1:1:1:1:1:1:1:1:64:17376:MNWNNT:0:1:1
Konica IP Controller:1:1:1:64:0:64:1:0:64:1:0:64:1:>64:64:0:1:1:2:1:1:1:0:1:64:2048:M:N:N:N
Konica Minolta Digital Copier/Printer:1:1:1:255:1:255:1:0:255:1:0:255:1:8:255:1:1:0:0:1:1:1:0:1:255:1:MNWNNT:0:1:1
Lantronix Printer:1:1:1:64:0:64:1:0:64:1:0:64:1:8:64:1:1:1:1:1:1:1:1:1:64:511:M:N:N:N
Lantronix Printer:1:1:1:64:0:64:1:0:64:1:0:64:1:8:64:1:1:1:1:3:1:1:1:1:64:255:M:N:N:N
Lantronix Printer:1:1:1:64:0:64:1:0:64:1:0:64:1:8:64:1:1:1:2:1:1:1:1:1:64:511:M:N:N:N
Lantronix SCS1600/SCS3200 Console Server:0:1:0:64:0:64:1:0:64:1:0:64:1:8:64:0:1:0:2:1:1:1:0:1:64:2048:M:N:N:N
Lantronix Universal Device Server:1:1:1:64:0:64:1:0:64:1:0:64:1:8:64:1:1:1:2:1:1:1:1:1:64:127:M:N:N:N
Lantronix Universal Device Server:1:1:1:64:0:64:1:0:64:1:0:64:1:8:64:1:1:1:2:1:1:1:1:1:64:255:M:N:N:N
Lexmark Printer:0:1:0:255:0:255:1:0:255:1:0:255:1:8:255:0:1:1:2:1:1:1:0:1:255:1010:M:N:N:N
Lexmark Printer:0:1:0:255:0:255:1:0:255:1:0:255:1:8:255:0:1:1:2:1:1:1:0:1:255:15346:M:N:N:
Lexmark Printer:1:0:1:255:1:255:0:0:255:0:0:255:0:>64:255:1:0:1:1:1:1:1:1:0:255:1448:MSTNW:0:1:1
Lexmark Printer:1:1:1:255:1:255:1:0:255:1:0:255:1:8:255:1:1:1:1:1:1:1:1:1:255:2896:MNWNNT:0:1:1
Lexmark Printer:1:1:1:255:1:255:1:0:255:1:0:255:1:8:255:1:1:1:2:1:1:1:1:1:255:2896:MNWNNT:0:1:1
Linksys Access Hub WAP11:1:1:0:64:0:64:1:0:64:1:0:64:1:8:64:0:1:1:1:1:1:1:0:1:64:4608:M:N:N:N
Linksys PAP2 Phone Adapter:1:1:0:255:0:255:1:0:255:1:0:255:1:8:255:0:1:1:2:1:1:1:0:1:255:16000:M:N:N:N
Linksys Router:1:1:0:255:0:255:1:0:255:1:0:255:1:8:255:0:1:1:2:1:1:1:0:1:255:5840:M:N:N:N
Linksys Router:1:1:0:255:0:255:1:0:255:1:0:255:1:8:255:0:1:1:2:3:1:1:0:0:255:5840:M:N:N:N
Linksys Router:1:1:1:255:1:255:1:1:255:1:0:255:1:8:255:1:1:0:0:3:>20:3:0:1:64:8760:MNWNNT:0:1:1
Linksys Router:1:S:0:255:0:255:1:0:255:1:0:255:1:8:255:0:S:1:1:1:1:1:0:0:255:5840:M:N:N:N
Linksys Router:1:S:0:64:0:64:1:0:64:1:0:64:1:8:64:0:S:1:1:1:1:1:0:0:64:5840:M:N:N:N
Linksys Router::1:S:0:255:0:255:1:0:255:1:0:255:1:8:255:0:S:2:2:1:1:1:1:1:128:64240:MNWNNTNNS:0:0:0
Linksys Wireless Access Point:0:1:0:64:1:64:1:0:64:1:0:64:1:>64:64:0:1:1:2:1:1:1:1:0:64:5792:MSTNW:7:1:1
Linksys Wireless Access Point:1:1:0:64:0:64:1:0:64:1:0:64:1:8:64:0:1:1:2:1:1:1:0:1:64:4608:M:N:N:N
Linksys Wireless WebCam:1:1:0:64:1:64:1:0:64:1:0:64:1:>64:64:0:1:1:2:1:1:1:0:1:64:16352:MM:N:N:N
Linux Kernel 2.0:1:1:0:64:1:64:1:0:64:1:0:64:1:>64:64:0:1:1:1:1:1:1:0:1:64:16352:M:N:N:N
Linux Kernel 2.2:1:1:0:255:1:255:1:0:255:1:0:255:1:64:255:0:1:1:1:1:1:1:1:1:64:16060:MSTNW:0:1:1
Linux Kernel 2.2:1:1:0:255:1:255:1:0:255:1:0:255:1:>64:255:0:1:1:1:1:1:1:1:1:64:32120:MSTNW:0:1:1
Linux Kernel 2.2:1:1:0:255:1:255:1:0:255:1:0:255:1:>64:255:0:1:1:2:1:1:1:1:1:64:16060:MSTNW:0:1:1
Linux Kernel 2.2:1:1:0:255:1:255:1:0:255:1:0:255:1:>64:255:0:1:1:2:1:1:1:1:1:64:32120:MSTNW:0:1:1
Linux Kernel 2.4:1:0:0:64:1:64:0:0:64:0:0:64:0:>64:64:0:0:1:2:1:1:1:1:0:64:5792:MSTNW:0:1:1
Linux Kernel 2.4:1:0:1:255:1:255:0:0:255:0:0:255:0:>64:255:1:1:1:1:1:1:1:1:0:64:5792:MSTNW:0:1:1
Linux Kernel 2.4:1:1:0:255:0:255:1:0:255:1:0:255:1:>64:255:0:1:1:1:1:1:1:1:0:64:5792:MSTNW:0:1:1
Linux Kernel 2.4:1:1:0:255:0:255:1:0:255:1:0:255:1:>64:255:0:1:1:2:1:1:1:1:0:64:5792:MSTNW:0:1:1
Linux Kernel 2.4:1:1:0:255:0:255:1:0:255:1:0:255:1:>64:255:0:1:2:2:1:1:1:1:0:64:5792:MSTNW:0:1:1
Linux Kernel 2.4:1:1:0:255:1:255:1:0:255:1:0:255:1:64:255:0:1:1:1:1:1:1:1:1:128:5792:MSTNW:0:1:1
Linux Kernel 2.4:1:1:0:255:1:255:1:0:255:1:0:255:1:64:255:0:1:1:1:1:1:1:1:1:64:5792:MSTNW:0:1:1
Linux Kernel 2.4:1:1:0:255:1:255:1:0:255:1:0:255:1:>64:255:0:1:1:1:1:1:1:1:0:64:5792:MSTNW:0:1:1
Linux Kernel 2.4:1:1:0:255:1:255:1:0:255:1:0:255:1:>64:255:0:1:1:2:1:1:1:1:0:64:5792:MSTNW:0:1:1
Linux Kernel 2.4:1:1:0:255:1:255:1:0:255:1:0:255:1:>64:255:0:1:1:2:1:1:1:1:0:64:5840:MNW:0:N:N
Linux Kernel 2.4:1:1:0:64:0:64:1:0:64:1:0:64:1:>64:64:0:1:1:1:1:1:1:1:0:64:5792:MSTNW:0:1:1
Linux Kernel 2.4:1:1:0:64:0:64:1:0:64:1:0:64:1:>64:64:0:1:1:2:1:1:1:1:1:64:5616:MSTNW:0:1:1
Linux Kernel 2.4:1:1:0:64:0:64:1:0:64:1:0:64:1:>64:64:0:1:1:2:1:1:1:1:1:64:5792:MSTNW:0:1:1
Linux Kernel 2.4:1:1:0:64:0:64:1:0:64:1:0:64:1:>64:64:0:1:2:1:3:1:1:1:0:64:5792:MSTNW:0:1:1
Linux Kernel 2.4:1:1:0:64:0:64:1:0:64:1:0:64:1:>64:64:0:1:2:2:1:1:3:0:0:64:5792:MSTNW:0:1:1
Linux Kernel 2.4:1:1:0:64:1:64:1:0:64:1:0:64:1:8:64:0:1:1:1:1:1:1:1:1:64:5792:MTWSN:0:1:1
Linux Kernel 2.4:1:1:0:64:1:64:1:0:64:1:0:64:1:>64:255:0:1:1:1:1:1:1:1:0:64:5792:MSTNW:0:1:1
Linux Kernel 2.4:1:1:0:64:1:64:1:0:64:1:0:64:1:>64:255:0:1:1:1:3:1:1:1:0:64:5792:MSTNW:0:1:1
Linux Kernel 2.4:1:1:0:64:1:64:1:0:64:1:0:64:1:>64:255:0:1:1:2:1:1:1:1:0:64:5760:MSTNW:0:1:1
Linux Kernel 2.4:1:1:0:64:1:64:1:0:64:1:0:64:1:>64:255:0:1:1:2:1:1:1:1:0:64:5792:MSTNW:0:1:1
Linux Kernel 2.4:1:1:0:64:1:64:1:0:64:1:0:64:1:>64:255:0:1:1:2:1:1:1:1:1:128:6144:MWNSNN:0:N:N
Linux Kernel 2.4:1:1:0:64:1:64:1:0:64:1:0:64:1:>64:255:0:1:1:2:1:1:1:1:1:64:5792:MSTNW:0:1:1
Linux Kernel 2.4:1:1:0:64:1:64:1:0:64:1:0:64:1:>64:64:0:1:1:1:1:1:1:0:1:64:5592:MSTNW:0:1:1
Linux Kernel 2.4:1:1:0:64:1:64:1:0:64:1:0:64:1:>64:64:0:1:1:1:1:1:1:1:0:64:5512:MSTNW:0:1:1
Linux Kernel 2.4:1:1:0:64:1:64:1:0:64:1:0:64:1:>64:64:0:1:1:1:1:1:1:1:0:64:5792:MSTNW:0:1:1
Linux Kernel 2.4:1:1:0:64:1:64:1:0:64:1:0:64:1:>64:64:0:1:1:1:1:1:1:1:1:64:5792:MSTNW:0:1:1
Linux Kernel 2.4:1:1:0:64:1:64:1:0:64:1:0:64:1:>64:64:0:1:1:1:3:1:1:1:0:64:5792:MSTNW:0:1:1
Linux Kernel 2.4:1:1:0:64:1:64:1:0:64:1:0:64:1:>64:64:0:1:1:2:1:1:1:1:0:64:5792:MSTNW:0:1:1
Linux Kernel 2.4:1:1:0:64:1:64:1:0:64:1:0:64:1:>64:64:0:1:1:2:1:1:1:1:1:64:5792:MSTNW:0:1:1
Linux Kernel 2.4:1:1:0:64:1:64:1:0:64:1:0:64:1:>64:64:0:1:2:2:1:1:1:1:1:64:5792:MSTNW:0:1:1
Linux Kernel 2.6:0:1:0:64:1:64:1:0:64:1:0:64:1:>64:64:0:1:1:2:1:1:1:1:0:64:5792:MSTNW:2:1:1
Linux Kernel 2.6:0:1:0:64:1:64:1:0:64:1:0:64:1:>64:64:0:1:1:2:1:1:1:1:0:64:5792:MSTNW:0:1:1
Linux Kernel 2.6:0:1:0:64:1:64:1:0:64:1:0:64:1:>64:255:0:1:1:2:1:1:1:1:0:64:5840:MNNSNW:2:N:N
Linux Kernel 2.6:1:1:0:128:0:128:1:0:128:1:0:128:1:>64:128:0:1:1:2:1:1:3:0:1:128:64240:M:N:N:N
Linux Kernel 2.6:1:1:0:64:0:64:1:0:64:1:0:64:1:>64:255:0:1:1:1:1:1:1:1:0:64:5792:MSTNW:0:1:1
Linux Kernel 2.6:1:1:0:64:0:64:1:0:64:1:0:64:1:>64:255:0:1:1:2:1:1:1:1:0:64:5792:MSTNW:2:1:1
Linux Kernel 2.6:1:1:0:64:0:64:1:0:64:1:0:64:1:>64:64:0:1:1:1:1:1:1:1:0:64:5792:MSTNW:2:1:1
Linux Kernel 2.6:1:1:0:64:0:64:1:0:64:1:0:64:1:>64:64:0:1:1:2:1:1:1:1:0:64:5792:MST:N:1:1
Linux Kernel 2.6:1:1:0:64:0:64:1:0:64:1:0:64:1:>64:64:0:1:1:2:1:1:1:1:0:64:5792:MSTNW:2:1:1
Linux Kernel 2.6:1:1:0:64:0:64:1:0:64:1:0:64:1:>64:64:0:1:2:1:1:1:3:0:0:64:5792:MSTNW:0:1:1
Linux Kernel 2.6:1:1:0:64:1:64:1:0:64:1:0:64:1:>64:255:0:1:1:1:1:1:1:1:0:64:5840:MNNSNW:0:N:N
Linux Kernel 2.6:1:1:0:64:1:64:1:0:64:1:0:64:1:>64:255:0:1:1:2:1:1:1:1:0:64:5792:MSTNW:2:1:
Linux Kernel 2.6:1:1:0:64:1:64:1:0:64:1:0:64:1:>64:255:0:1:1:2:1:1:1:1:0:64:5792:MSTNW:2:1:1
Linux Kernel 2.6:1:1:0:64:1:64:1:0:64:1:0:64:1:>64:255:0:1:2:2:1:1:1:1:0:64:5792:MSTNW:2:1:1
Linux Kernel 2.6:1:1:0:64:1:64:1:0:64:1:0:64:1:>64:64:0:1:1:1:1:1:1:1:0:64:5760:MSTNW:0:1:1
Linux Kernel 2.6:1:1:0:64:1:64:1:0:64:1:0:64:1:>64:64:0:1:1:1:1:1:1:1:0:64:5792:MSTNW:2:1:1
Linux Kernel 2.6:1:1:0:64:1:64:1:0:64:1:0:64:1:>64:64:0:1:1:1:1:1:1:1:0:64:5792:MSTNW:7:1:1
Linux Kernel 2.6:1:1:0:64:1:64:1:0:64:1:0:64:1:>64:64:0:1:1:2:1:1:1:1:0:64:4452:MSTNW:2:1:1
Linux Kernel 2.6:1:1:0:64:1:64:1:0:64:1:0:64:1:>64:64:0:1:1:2:1:1:1:1:0:64:5792:MSTNW:0:1:1
Linux Kernel 2.6:1:1:0:64:1:64:1:0:64:1:0:64:1:>64:64:0:1:1:2:1:1:1:1:0:64:5792:MSTNW:2:1:1
Linux Kernel 2.6:1:1:0:64:1:64:1:0:64:1:0:64:1:>64:64:0:1:1:2:1:1:1:1:0:64:5792:MSTNW:3:1:1
Linux Kernel 2.6:1:1:0:64:1:64:1:0:64:1:0:64:1:>64:64:0:1:1:2:1:1:1:1:0:64:5840:M:N:N:N
Linux Kernel 2.6:1:1:0:64:1:64:1:0:64:1:0:64:1:>64:64:0:1:1:2:1:1:3:0:0:64:1300:MSTNW:2:1:1
Linux Kernel 2.6:1:1:0:64:1:64:1:0:64:1:0:64:1:>64:64:0:1:1:2:3:1:1:1:0:64:5792:MSTNW:2:1:1
Linux Kernel 2.6:1:S:1:255:1:255:S:0:255:S:0:255:S:8:255:0:1:1:1:1:1:1:1:0:64:5792:MSTNW:0:1:1
Lucent ADSL Router:1:1:0:255:0:255:1:0:255:1:0:255:1:8:64:0:1:1:2:1:1:1:1:1:64:512:M:N:N:N
Lucent Cajun:1:S:0:64:1:64:S:1:64:S:0:64:S:8:64:0:1:1:2:1:1:1:0:1:64:4096:M:N:N:N
Mac OS 8.6:1:1:1:255:0:255:1:1:255:1:0:255:1:64:255:1:1:1:2:1:1:1:1:1:255:17520:MW:0:N:N
Mac OS 8:1:1:1:255:0:255:1:1:255:1:0:255:1:64:255:1:1:2:1:3:1:1:1:1:255:1380:MW:0:N:N
Mac OS 9:1:1:1:255:0:255:1:1:255:1:0:255:1:64:255:1:1:1:2:1:1:1:1:1:255:32768:MWNNNT:0:1:1
Mac OS 9:1:1:1:255:0:255:1:1:255:1:0:255:1:64:255:1:1:2:1:3:1:1:1:1:255:1380:MWNNNT:0:1:1
Mac OS X 10.2:1:1:1:64:1:64:1:0:64:1:0:64:1:8:64:1:1:0:1:1:1:1:1:1:64:33304:MNWNNT:0:1:1
Mac OS X 10.3:1:1:1:64:0:64:1:0:64:1:0:64:1:8:64:1:1:0:1:1:1:1:1:1:64:1460:MNWNNT:0:1:1
Mac OS X 10.3:1:1:1:64:0:64:1:0:64:1:0:64:1:8:64:1:1:0:1:1:1:1:1:1:64:33304:MNWNNT:0:1:1
Mac OS X 10.3:1:1:1:64:0:64:1:0:64:1:0:64:1:8:64:1:1:0:1:1:1:1:1:1:64:65535:MNWNNT:0:1:1
Mac OS X 10.3:1:1:1:64:0:64:1:0:64:1:0:64:1:8:64:1:1:0:1:1:1:1:1:1:64:65535:MNWNNT:1:1:1
Mac OS X 10.3:1:1:1:64:0:64:1:0:64:1:0:64:1:8:64:1:1:0:2:1:1:1:1:1:64:33304:MNWNNT:0:1:1
Mac OS X 10.3:1:1:1:64:0:64:1:0:64:1:0:64:1:8:64:1:1:0:2:1:1:1:1:1:64:65535:MNWNNT:0:1:1
Mac OS X 10.3:0:1:1:64:0:64:1:0:64:1:0:64:1:8:64:1:1:0:2:1:1:1:1:1:64:65535:MNWNNT:1:1:1
Mac OS X 10.4:1:1:1:64:0:64:1:0:64:1:0:64:1:8:64:1:1:0:2:1:1:1:1:1:64:65535:MNWNNT:0:1:1
Madge Smart Ringswitch:0:1:0:32:1:32:1:0:32:1:0:32:1:8:32:0:1:1:2:1:1:3:0:1:32:500::N:N:N
Microsoft Longhorn:0:1:0:128:0:128:1:0:128:1:0:128:1:64:128:0:1:1:1:1:1:1:1:1:128:16384:MWNST:0:1:1
Microsoft Windows 2000 Professional Service Pack 3:0:1:1:128:1:128:1:0:128:1:0:128:1:8:128:0:1:1:2:1:1:1:1:1:128:64240:MNWNNTNNS:0:0:0
Microsoft Windows 2000 Professional Service Pack 4:0:1:1:128:0:128:1:0:128:1:0:128:1:8:128:0:1:1:2:1:1:1:1:1:128:65535:MNWNNTNNS:0:0:0
Microsoft Windows 2000 Professional Service Pack 4:0:1:1:128:1:128:1:0:128:1:0:128:1:8:128:0:1:1:1:1:1:1:1:1:128:32767:MNWNNS:0:N:N
Microsoft Windows 2000 Professional Service Pack 4:0:1:1:128:1:128:1:0:128:1:0:128:1:8:128:0:1:1:1:1:1:1:1:1:128:8760:MNWNNTNNS:0:0:
Microsoft Windows 2000 Professional Service Pack 4:0:1:1:128:1:128:1:0:128:1:0:128:1:8:128:0:1:1:1:3:1:1:0:1:128:17520:MNWNNTNNS:0:0:0
Microsoft Windows 2000 Professional Service Pack 4:0:1:1:128:1:128:1:0:128:1:0:128:1:8:128:0:1:1:2:1:1:1:1:1:128:17520:MNWNNTNNS:0:0:0
Microsoft Windows 2000 Professional:0:1:1:128:1:128:1:0:128:1:0:128:1:8:128:0:1:1:1:1:1:1:1:1:128:64512:MNWINNTNNS:0:0:0
Microsoft Windows 2000 Professional:0:1:1:128:1:128:1:0:128:1:0:128:1:8:128:0:1:1:1:1:1:1:1:1:128:64512:MNWNNTNNS:0:0:0 
Microsoft Windows 2000 Server Service Pack 2:0:1:1:128:1:128:1:0:128:1:0:128:1:8:128:0:1:1:1:1:1:1:1:1:128:16872:MNWNNTNNS:0:0:0
Microsoft Windows 2000 Server Service Pack 4:0:1:1:128:0:128:1:0:128:1:0:128:1:8:128:0:1:1:1:1:1:1:1:1:128:17520:MNWNNTNNS:0:0:0
Microsoft Windows 2000 Server Service Pack 4:0:1:1:128:0:128:1:0:128:1:0:128:1:8:128:0:1:1:1:1:1:1:1:1:128:65535:MNWNNTNNS:0:0:0
Microsoft Windows 2000 Server Service Pack 4:0:1:1:128:0:128:1:0:128:1:0:128:1:8:128:0:1:1:2:3:1:1:1:1:128:17520:MNWNNTNNS:0:0:0
Microsoft Windows 2000 Server Service Pack 4:0:1:1:128:0:128:1:0:128:1:0:128:1:8:128:0:1:2:1:1:1:1:1:1:128:17640:MNWNNTNNS:0:0:0
Microsoft Windows 2000 Server Service Pack 4:0:1:1:128:1:128:1:0:128:1:0:128:1:8:128:0:1:1:1:1:1:1:0:1:128:65535:MNWNNTNNS:0:0:0
Microsoft Windows 2000 Server Service Pack 4:0:1:1:128:1:128:1:0:128:1:0:128:1:8:128:0:1:2:1:1:1:1:1:1:128:65535:MNWNNTNNS:0:0:0
Microsoft Windows 2000 Server:0:1:1:128:1:128:1:0:128:1:0:128:1:8:128:0:1:1:1:1:1:1:1:1:128:65535:MNWNNTNNS:0:0:0
Microsoft Windows 2000 Server:0:1:1:128:1:128:1:0:128:1:0:128:1:8:128:0:1:1:2:1:1:1:1:1:128:65535:MNWNNTNNS:0:0:0
Microsoft Windows 2003 Server:0:1:0:128:0:128:1:0:128:1:0:128:1:>64:128:0:1:2:1:1:1:3:0:1:128:17520:MNWNNTNNS:0:0:0
Microsoft Windows 2003 Server:0:1:1:128:0:128:1:0:128:1:0:128:1:>64:128:0:1:1:2:1:1:1:1:1:128:65535:MNWNNTNNS:0:0:0
Microsoft Windows 2003 Server:0:1:1:128:1:128:1:0:128:1:0:128:1:>64:128:0:1:1:1:1:1:1:0:1:128:16384:MNWNNTNNS:0:0:0
Microsoft Windows 2003 Server:0:1:1:128:1:128:1:0:128:1:0:128:1:>64:128:0:1:1:1:1:1:1:1:1:128:17520:MNWNNTNNS:0:0:0
Microsoft Windows 2003 Server:0:1:1:128:1:128:1:0:128:1:0:128:1:>64:128:0:1:1:1:1:1:1:1:1:128:65535:MNWNNTNNS:0:0:0
Microsoft Windows 2003 Server:0:1:1:128:1:128:1:0:128:1:0:128:1:>64:128:0:1:1:2:1:1:1:0:1:128:16384:MNWNNTNNS:0:0:0
Microsoft Windows 2003 Server:0:1:1:128:1:128:1:0:128:1:0:128:1:>64:128:0:1:1:2:1:1:1:1:1:128:17520:MNWNNTNNS:0:0:0
Microsoft Windows 2003 Server:1:1:0:64:1:64:1:0:64:1:0:64:1:>64:255:0:1:1:2:1:1:1:0:1:128:16384:MNWNNTNNS:0:0:0
Microsoft Windows 2003 Server:1:1:0:64:1:64:1:0:64:1:0:64:1:>64:64:0:1:1:1:1:1:1:1:1:128:17520:MNWNNTNNS:0:0:0
Microsoft Windows 95:0:1:1:128:0:128:1:0:128:1:0:128:1:8:128:0:1:1:1:1:1:1:1:1:128:8760:MNWNNTNNS:0:0:0
Microsoft Windows 95:0:1:1:128:0:128:1:1:128:1:0:128:1:8:128:0:1:1:1:1:1:1:1:1:128:8760:MNWNNTNNS:0:0:0
Microsoft Windows 95:0:1:1:128:1:128:1:1:128:1:0:128:1:8:128:0:1:1:2:1:1:1:1:1:128:5840:MNNS:N:N:N
Microsoft Windows 95:0:1:1:32:0:32:1:1:32:1:0:32:1:8:32:0:1:1:1:1:1:1:1:1:32:8760:M:N:N:N
Microsoft Windows 98:0:1:1:128:1:128:1:1:128:1:0:128:1:8:128:0:1:1:1:1:1:1:1:1:128:8760:MNNS:N:N:N
Microsoft Windows 98:0:1:1:128:1:128:1:1:128:1:0:128:1:8:128:0:1:1:1:3:1:1:1:1:128:8760:MNNS:N:N:N
Microsoft Windows 98:0:1:1:128:1:128:1:1:128:1:0:128:1:8:128:0:1:1:2:1:1:1:1:1:128:5840:MNNS:N:N:N
Microsoft Windows 98:0:1:1:128:1:128:1:1:128:1:0:128:1:8:128:0:1:1:2:1:1:1:1:1:128:8760:MNNS:N:N:N
Microsoft Windows 98:0:1:1:64:1:64:1:1:64:1:0:64:1:8:64:0:1:1:1:1:1:1:0:1:64:8576:MNNS:N:N:N
Microsoft Windows 98:0:1:1:64:1:64:1:1:64:1:0:64:1:8:64:0:1:1:1:1:1:1:1:1:64:32767:MNNS:N:N:N
Microsoft Windows 98:0:1:1:64:1:64:1:1:64:1:0:64:1:8:64:0:1:1:1:1:1:1:1:1:64:64240:MNNS:N:N:N
Microsoft Windows 98:0:1:1:64:1:64:1:1:64:1:0:64:1:8:64:0:1:1:2:1:1:1:0:1:64:65535:MNNS:N:N:N
Microsoft Windows CE:0:1:1:128:1:128:1:0:128:1:0:128:1:8:128:0:1:1:2:1:1:1:1:1:128:32768:MNWNNTNNS:0:0:0
Microsoft Windows ME:0:1:1:128:1:128:1:0:128:1:0:128:1:8:128:0:1:1:1:1:1:1:1:1:128:4736:MNWNNTNNS:0:0:0
Microsoft Windows ME:0:1:1:128:1:128:1:1:128:1:0:128:1:8:128:0:1:2:1:1:1:1:1:1:128:8576:MNNS:N:N:N
Microsoft Windows ME:0:1:1:64:1:64:1:0:64:1:0:64:1:8:64:0:1:1:1:3:1:1:1:1:64:32767:MNWNNTNNS:0:0:0
Microsoft Windows Mobile 2003 Second Edition:0:1:1:128:1:128:1:0:128:1:0:128:1:8:128:0:1:1:1:1:1:1:1:1:128:32768:MNWNNTNNS:0:0:0
Microsoft Windows Mobile 5.0:0:1:1:128:1:128:1:0:128:1:0:128:1:>64:128:0:1:1:1:1:1:1:1:1:128:65535:MNWNNTNNS:1:0:0
Microsoft Windows NT 4.0 Server (pre-SP3):0:1:1:128:0:128:1:1:128:1:0:128:1:8:128:0:1:1:1:1:1:1:1:1:128:8760:M:N:N:N
Microsoft Windows NT 4.0 Server:0:1:1:128:0:128:1:0:128:1:0:128:1:8:128:0:1:1:1:1:1:1:1:1:128:8280:M:N:N:N
Microsoft Windows NT 4.0 Server:0:1:1:128:0:128:1:0:128:1:0:128:1:8:128:0:1:1:1:1:1:1:1:1:128:8760:M:N:N:N
Microsoft Windows NT 4.0 Server:0:1:1:128:0:128:1:0:128:1:0:128:1:8:128:0:1:1:1:3:1:1:1:1:128:8760:M:N:N:N
Microsoft Windows NT 4.0 Terminal Server:0:1:0:128:1:128:1:0:128:1:1:128:1:8:128:0:1:2:2:1:1:1:0:1:128:32752:M:N:N:N
Microsoft Windows NT 4.0 Workstation (pre-SP3):0:1:1:128:0:128:1:1:128:1:0:128:1:8:128:0:1:1:1:1:1:1:1:1:128:8760:M:N:N:N
Microsoft Windows NT 4.0 Workstation:0:1:1:128:0:128:1:0:128:1:0:128:1:8:128:0:1:1:1:1:1:1:1:1:128:8280:M:N:N:N
Microsoft Windows NT 4.0 Workstation:0:1:1:128:0:128:1:0:128:1:0:128:1:8:128:0:1:1:1:1:1:1:1:1:128:8760:M:N:N:N
Microsoft Windows NT 4.0:0:1:1:128:0:128:1:0:128:1:0:128:1:8:128:0:1:1:2:1:1:1:1:1:128:8760:M:N:N:N
Microsoft Windows XP Home Edition:0:1:0:128:0:128:1:0:128:1:0:128:1:8:128:0:1:1:1:1:1:1:0:1:128:17640:MNWNNTNNS:0:0:0
Microsoft Windows XP Home Edition:0:1:1:128:1:128:1:0:128:1:0:128:1:8:128:0:1:1:1:1:1:1:0:1:128:17680:MNWNNTNNS:0:0:0
Microsoft Windows XP Home Edition:0:1:1:128:1:128:1:0:128:1:0:128:1:8:128:0:1:2:1:1:1:1:1:1:128:64240:MNWNNTNNS:0:0:0
Microsoft Windows XP Profesional:0:1:1:128:1:128:1:0:128:1:0:128:1:>64:128:0:1:1:2:1:1:1:1:1:128:65535:MNWNNTNNS:0:0:0
Microsoft Windows XP Professional SP1:0:1:1:128:1:128:1:0:128:1:0:128:1:8:128:0:1:1:2:1:1:1:1:1:128:64512:MNWNNTNNS:0:0:0
Microsoft Windows XP Professional SP2:0:1:1:64:1:64:1:0:64:1:0:64:1:>64:64:0:1:1:2:1:1:1:1:1:64:65535:MNWNNS:2:N:N
Microsoft Windows XP Professional:0:1:1:128:0:128:1:0:128:1:0:128:1:8:128:0:1:1:1:1:1:1:1:1:128:64240:MNWNNTNN:0:0:0
Microsoft Windows XP Professional:0:1:1:128:0:128:1:0:128:1:0:128:1:8:128:0:1:1:1:1:1:1:1:1:128:65280:MNWNNTNNS:0:0:0
Microsoft Windows XP Professional:0:1:1:128:1:128:1:0:128:1:0:128:1:8:128:0:1:1:1:1:1:1:0:1:128:16384:MNNS:N:N:N
Microsoft Windows XP Professional:0:1:1:128:1:128:1:0:128:1:0:128:1:8:128:0:1:1:1:1:1:1:0:1:128:17520:MNWNNTNNS:0:0:0
Microsoft Windows XP Professional:0:1:1:128:1:128:1:0:128:1:0:128:1:8:128:0:1:1:1:1:1:1:0:1:128:65340:MNWNNT:0:0:0
Microsoft Windows XP Professional:0:1:1:128:1:128:1:0:128:1:0:128:1:8:128:0:1:1:1:1:1:1:1:1:128:17520:MNWNNTNNS:0:0:0
Microsoft Windows XP Professional:0:1:1:128:1:128:1:0:128:1:0:128:1:8:128:0:1:1:1:1:1:1:1:1:128:17680:MNWNNTNNS:0:0:0
Microsoft Windows XP Professional:0:1:1:128:1:128:1:0:128:1:0:128:1:8:128:0:1:1:1:1:1:1:1:1:128:64240:MNWNNTNNS:0:0:0
Microsoft Windows XP Professional:0:1:1:128:1:128:1:0:128:1:0:128:1:8:128:0:1:1:1:1:1:1:1:1:128:64440:MNWNNTNNS:0:0:0
Microsoft Windows XP Professional:0:1:1:128:1:128:1:0:128:1:0:128:1:8:128:0:1:1:1:1:1:1:1:1:128:65268:MNWNNTNNS:0:0:0
Microsoft Windows XP Professional:0:1:1:128:1:128:1:0:128:1:0:128:1:8:128:0:1:1:1:1:1:1:1:1:128:65520:MNWNNTNNS:0:0:0
Microsoft Windows XP Professional:0:1:1:128:1:128:1:0:128:1:0:128:1:>64:128:0:1:1:2:1:1:1:1:1:128:65535:MNWNNS:1:N:N
Microsoft Windows XP Professional:0:1:1:64:1:64:1:0:64:1:0:64:1:8:64:0:1:1:1:1:1:1:1:1:64:64240:MNWNNS:2:N:N
Microsoft XP Professional Service Pack 2:0:1:1:128:1:128:1:0:128:1:0:128:1:>64:128:0:1:1:2:1:1:1:1:1:128:64512:MNWNNTNNS:0:0:0
Minolta QMS Printer:1:1:1:64:1:64:1:0:64:1:0:64:1:8:64:1:1:0:0:1:1:1:0:1:64:24576:MNWNNT:0:1:1
Motoroal DAC6000:1:1:1:64:1:64:1:0:64:1:0:64:1:8:64:1:1:1:2:1:1:1:1:1:64:24820:M:N:N:N
Motorola Vanguard:0:1:0:64:0:64:1:1:64:1:0:64:1:8:64:0:1:1:1:1:1:1:0:1:64:2048:M:N:N:N
Motorola Vanguard:0:1:0:64:0:64:1:1:64:1:0:64:1:8:64:0:1:1:2:1:1:1:0:1:64:2048:M:N:N:N
NCR MP-RAS SVR4 UNIX:1:1:1:64:1:64:1:0:64:1:0:64:1:8:64:1:1:1:1:1:1:1:1:1:64:24820:MNWNNT:0:1:1
NeXT:1:1:1:255:1:255:1:1:255:1:1:255:1:8:255:1:1:0:0:3:1:3:0:1:64:4096:MS:N:N:N
NetBSD 2.0:1:1:0:255:1:255:1:0:255:1:0:255:1:8:255:0:1:1:2:1:1:1:1:1:64:32768:MNWNNT:0:1:1
NetBSD 3.0:1:1:0:255:1:255:1:0:255:1:0:255:1:8:255:0:1:1:1:1:1:1:1:1:64:32768:MNWNNTSNN:0:1:1
NetGear ProSafe VPN Firewall (FVS318):1:S:1:64:0:64:1:0:64:1:0:64:1:X:X:X:X:X:X:X:X:X:0:1:32:4095:M:N:N:N
NetGear Router:1:1:0:255:1:255:1:0:255:1:0:255:1:>64:255:0:1:1:2:1:1:1:1:0:64:5792:MSTNW:0:1:1
NetGear Wireless Router (MR814):1:1:0:255:0:255:1:0:255:1:1:255:1:X:X:X:X:X:X:X:X:X:0:1:255:2048:M:N:N:N
Netcomm NB3 ADSL Modem:1:1:0:64:0:64:1:0:64:1:0:64:1:8:64:0:1:1:2:1:1:1:0:1:64:16000:M:N:N:N
Netilla Service Platform 4.0:1:1:0:64:1:64:1:0:64:1:0:64:1:>64:64:0:1:1:1:1:1:1:1:0:64:5840:MNNSNW:0:N:N
Netopia Router:1:1:0:255:0:255:1:0:255:1:0:255:1:8:255:0:1:1:1:1:1:1:0:1:255:2048:M:N:N:N
Netopia Router:1:1:0:255:0:255:1:0:255:1:0:255:1:8:255:0:1:1:1:1:1:1:0:1:255:8800:M:N:N:N
Netopia Router:1:1:0:255:0:255:1:0:255:1:0:255:1:8:255:0:1:1:1:1:1:1:1:1:64:57344:MNWNNT:0:1:1
Nexsan ATABeast disk vault server:1:1:0:255:0:255:1:0:255:1:0:255:1:8:255:0:1:1:2:1:1:1:0:1:255:8192:MTW:0:1:1
Nokia IPSO 3.1:1:1:1:255:1:255:1:1:255:1:0:255:1:>64:255:1:1:0:2:1:>20:1:0:1:64:16384:MNWNNT:0:1:1
Nokia IPSO 3.5:1:1:1:255:1:255:1:0:255:1:0:255:1:>64:255:1:1:0:1:1:1:1:0:1:64:16384:MNWNNT:0:1:1
Nokia IPSO 3.7:1:1:1:255:1:255:1:0:255:1:0:255:1:>64:255:1:1:0:1:1:1:1:0:1:64:16384:MNWNNT:0:1:1
Nokia IPSO 3.9:1:1:1:255:1:255:1:0:255:1:0:255:1:>64:255:1:1:0:2:1:1:1:0:1:64:17376:MNWNNT:0:1:1
Nokia IPSO Firewall:1:1:1:255:0:255:1:0:255:1:0:255:1:X:X:X:X:X:X:X:X:X:0:1:64:16384:MNWNNT:0:1:1
Nortel 6480 Router:1:1:0:64:1:64:1:0:64:1:0:64:1:8:255:0:1:1:1:1:1:1:0:1:32:4096::N:N:N
Nortel Baystack Switch:1:1:0:32:0:32:1:0:32:1:0:32:1:8:32:0:1:1:1:1:1:1:0:1:32:1024:M:N:N:N
Nortel Baystack Switch:1:1:0:32:0:32:1:0:32:1:0:32:1:8:32:0:1:1:2:1:1:1:0:1:32:1024:MS:N:N:N
Nortel Baystack Switch:1:1:0:64:0:64:1:0:64:1:0:64:1:8:64:0:1:1:1:1:1:1:0:1:64:1024:M:N:N:N
Nortel Baystack Switch:1:1:0:64:0:64:1:0:64:1:0:64:1:8:64:0:1:1:2:1:1:1:0:1:64:1024:M:N:N:N
Nortel Business Policy Switch:1:1:1:64:1:64:1:0:64:1:0:64:1:8:64:1:1:0:0:1:1:1:0:1:64:8192:MNW:0:N:N
Nortel Contivity:1:1:1:64:0:64:1:0:64:1:0:64:1:8:64:1:1:0:2:3:1:3:0:1:64:8760:MNWNNT:0:1:1
Nortel Coreswitch:1:1:0:255:1:255:1:0:255:1:0:255:1:>64:255:0:1:1:2:1:1:1:1:0:64:5840:MNW:0:N:N
Nortel Passport:1:S:1:255:0:255:1:0:255:1:0:255:1:8:255:1:1:0:0:1:1:1:0:1:32:4096:M:N:N:N 
Nortel Router:1:1:0:32:0:32:1:0:32:1:0:32:1:8:32:0:1:1:2:1:1:1:0:1:32:1024:MNNTNW:0:1:1
Nortel Switch:1:1:1:64:0:64:1:0:64:1:0:64:1:8:64:1:1:0:0:1:1:1:1:1:64:8192:MNWNNT:0:1:1
Nortel Switch:1:1:1:64:1:64:1:0:64:1:0:64:1:8:64:1:1:0:0:1:1:1:1:1:64:8192:MNWNNT:0:1:1
Novell Netware 5.1:1:1:0:128:0:128:1:0:128:1:0:128:1:8:128:0:1:1:1:1:1:1:1:1:128:6144:MWNSNN:0:N:N
Novell Netware 5.1:1:1:0:128:0:128:1:1:255:1:0:255:1:8:128:0:1:1:1:1:1:1:1:1:128:6144:MWNSNN:0:N:N
Novell Netware 5.1:1:1:0:128:0:128:1:1:255:1:0:255:1:8:128:0:1:1:1:1:1:1:1:1:128:8191:M:N:N:N
Novell Netware 5.6:1:1:0:128:0:128:1:0:128:1:0:128:1:8:128:0:1:1:1:1:1:1:1:1:128:6144:MWNSNN:0:N:N
Novell Netware 5.6:1:1:0:128:0:128:1:0:128:1:0:128:1:8:128:0:1:1:1:1:1:1:1:1:128:6144:MWNSNN:1:N:N
Novell Netware 5.7:1:1:0:128:0:128:1:0:128:1:0:128:1:8:128:0:1:1:2:1:1:1:1:1:128:6144:M:N:N:N
Novell Netware 6.0:1:1:0:128:0:128:1:0:128:1:0:128:1:8:128:0:1:1:1:1:1:1:1:1:128:6144:MWNSNN:0:N:N
Novell Netware 6.5:1:1:0:128:0:128:1:0:128:1:0:128:1:8:128:0:1:1:1:3:1:1:1:1:128:6143:MWNSNN:0:N:N
Novell Netware 6.5:1:1:0:128:0:128:1:0:128:1:0:128:1:8:128:0:1:1:1:3:1:1:1:1:128:6143:MWNSNN:0:N:N 
Novell Netware 6.5:1:1:0:128:0:128:1:0:128:1:0:128:1:8:128:0:1:1:2:1:1:1:1:1:128:6143:MWNSNN:0:N:N
OS/2 2.4:1:1:1:64:1:64:1:1:64:1:0:64:1:8:64:1:1:0:0:3:1:3:1:1:64:33580:MNW:0:N:N
OS/2 Warp 4.0 Advanced Server:1:1:1:255:1:255:1:1:255:1:1:255:1:8:255:1:1:0:0:3:1:3:0:1:64:28672:M:N:N:N
OS/2 Warp 4.0 Advanced Server:1:1:1:255:1:255:1:1:255:1:1:255:1:8:255:1:1:0:0:3:1:3:0:1:64:4096:M:N:N:N
OS/2 Warp 4.0:1:1:1:255:1:255:1:1:255:1:1:255:1:8:255:1:1:0:0:3:1:3:0:1:32:27588:M:N:N:N
OmniSwitch:1:1:1:32:1:32:1:1:32:1:1:32:1:8:32:1:1:0:0:1:1:1:0:1:32:4096::N:N:N
OpenBSD 2.7:0:1:0:64:0:64:1:0:64:1:0:64:1:8:255:0:1:2:2:1:>20:1:0:1:64:16500:MNNSNWNNT:0:1:1
OpenBSD 2.9:1:1:1:255:0:255:1:0:255:1:0:255:1:8:255:0:1:2:1:1:>20:1:1:1:64:16992:MNNSNWNNT:0:1:1
OpenBSD 3.1:1:1:1:255:1:255:1:0:255:1:0:255:1:8:255:0:1:1:2:1:>20:1:1:1:64:17376:MNNSNWNNT:0:1:1
OpenBSD 3.2:1:1:1:255:1:255:1:0:255:1:0:255:1:8:255:0:1:1:2:1:>20:1:1:1:64:17280:MNNSNWNNT:0:1:1
OpenBSD 3.4:1:1:1:255:1:255:1:0:255:1:0:255:1:8:255:0:1:1:1:1:1:1:1:1:64:17376:MNNSNWNNT:0:1:1
OpenBSD 3.5:1:1:1:255:1:255:1:0:255:1:0:255:1:8:255:0:1:1:1:1:1:1:0:1:64:16384:MNNSNWNNT:0:1:1
OpenBSD 3.5:1:1:1:255:1:255:1:0:255:1:0:255:1:8:255:0:1:1:2:1:1:1:1:1:64:16384:MNNSNWNNT:0:1:1
OpenBSD 3.5:1:1:1:255:1:255:1:0:255:1:0:255:1:8:255:0:1:2:2:1:1:1:1:1:64:16384:MNNSNWNNT:0:1:1
OpenBSD 3.6:1:1:0:255:1:255:1:0:255:1:0:255:1:8:255:0:1:1:2:3:1:3:1:1:64:16384:MNNSNWNNT:0:1:1
OpenBSD 3.6:1:1:1:255:0:255:1:0:255:1:0:255:1:8:64:0:S:2:2:3:1:1:1:0:64:5792:MSTNW:0:1:1
OpenBSD 3.6:1:1:1:255:1:255:1:0:255:1:0:255:1:8:255:0:1:1:1:1:1:1:0:1:64:65335:MNNSNWNNT:0:1:1
OpenBSD 3.6:1:1:1:255:1:255:1:0:255:1:0:255:1:8:255:0:1:1:2:1:1:1:1:1:64:16384:MNNSNWNNT:0:1:1
OpenBSD 3.7:1:1:1:255:0:255:1:0:255:1:0:255:1:8:255:0:1:1:2:1:1:1:1:1:64:16384:MNNSNWNNT:0:1:1
OpenBSD 3.8:1:1:1:255:1:255:1:0:255:1:0:255:1:8:255:0:1:1:1:1:1:1:1:1:64:16384:MNNSNWNNT:0:1:1
OpenVMS 7.1-1H2:1:1:0:255:1:255:1:1:255:1:1:255:1:8:255:0:1:1:0:3:1:3:0:1:128:3000::N:N:N:
OpenVMS 7.1:1:1:1:255:1:255:1:1:255:1:1:255:1:8:255:1:1:0:0:3:1:3:1:1:64:6144:MNWNNT:0:1:1
OpenVMS 7.2:1:1:1:64:1:64:1:0:64:1:1:64:1:8:64:1:1:0:1:1:1:1:0:1:64:33580:MNW:0:N:N
OpenVMS 7.2:1:1:1:64:1:64:1:0:64:1:1:64:1:8:64:1:1:0:1:1:1:1:0:1:64:4380:MNW:0:N:N
OpenVMS:1:1:1:64:1:64:1:0:64:1:1:64:1:8:64:1:1:1:1:1:1:1:0:1:64:61440:MNW:0:N:N
Orinoco BG 2000 Wireless Internet Gateway:1:1:1:64:1:64:1:0:64:1:0:64:1:8:64:1:1:0:0:1:1:1:1:0:64:5792:MSTNW:0:1:1
PSOSystem 2.2:1:1:255:1:255:1:1:255:1:1:255:1:8:255:1:1:1:0:1:1:1:0:1:64:4096:M:N:N:N
PacketShaper 4.1:1:1:1:255:1:255:1:1:255:1:1:255:1:8:255:1:1:1:0:1:1:3:0:1:64:4096:M:N:N:N
PacketShaper 6:1:1:1:255:1:255:1:1:255:1:1:255:1:8:255:1:1:1:0:3:1:3:0:1:64:1460::N:N:NA
PacketShaper 6:1:1:1:255:1:255:1:1:255:1:1:255:1:8:255:1:1:1:0:3:1:3:0:1:64:4096::N:N:N
Perle CONSOLESERVER 9000:1:1:1:255:1:255:1:0:255:1:1:255:1:8:255:1:1:0:0:3:1:3:0:1:64:2048:M:N:N:N
Phaser 850DP:1:1:0:128:0:128:1:0:128:1:0:128:1:8:128:0:1:1:1:1:1:1:0:1:128:2920:M:N:N:N
PolyCom ViewStation:0:1:1:64:0:64:1:0:64:1:0:64:1:64:64:0:1:1:1:1:1:1:0:1:64:23360:M:N:N:N
PolyCom ViewStation:0:1:1:64:0:64:1:0:64:1:0:64:1:64:64:0:1:1:2:1:1:1:0:1:64:23360:M:N:N:N
Polycom SoundPoint IP Phone:1:1:1:64:1:64:1:0:64:1:0:64:1:8:64:1:1:0:0:3:1:3:0:1:64:8192:M:N:N:N
Polycom Viewstation:0:1:1:64:0:64:1:0:64:1:0:64:1:64:64:0:1:1:1:1:1:1:0:1:64:23360:M:N:N:N
PowerShow NetworKam webcam:1:1:0:64:0:64:1:0:64:1:0:64:1:8:64:0:1:1:1:1:1:1:0:1:64:2144:M:N:N:N 
PowerTV OS:1:1:1:255:0:255:1:0:255:1:0:255:1:8:255:1:1:0:0:1:1:1:0:1:64:65535:MNWNNT:1:1:1
Prisma Digital Transport System:1:1:1:255:1:255:1:1:255:1:1:255:1:8:255:1:1:1:0:1:1:1:0:1:64:4096:M:N:N:N
QNX 4.2:1:1:1:255:1:255:1:1:255:1:1:255:1:8:255:1:1:0:0:3:>20:3:0:1:64:7300:M:N:N:N
QNX 6.2:1:1:0:255:1:255:1:0:255:1:0:255:1:8:255:0:1:1:2:1:1:1:0:1:255:16384:MNWNNT:0:1:1
QNX 6.3:1:1:0:255:0:255:1:0:255:1:0:255:1:8:255:0:1:1:2:1:1:1:0:1:255:16384:MNWNNT:0:1:1
Quantum Snap Server:1:1:1:255:0:255:1:0:255:1:0:255:1:8:255:1:1:0:0:3:1:3:0:1:32:8760:M:N:N:N
Radware Apsolute Appliance:1:1:1:64:1:64:1:1:64:1:0:64:1:8:64:0:1:1:2:1:1:1:0:1:64:2048:M:N:N:N
Raptor Firewall:1:1:1:64:1:64:1:1:64:1:1:64:1:8:64:1:1:1:1:1:1:1:0:1:64:61440:MNW:0:N:N 
Ricoh Printer:1:1:1:255:1:255:1:0:255:1:0:255:1:8:255:1:1:0:0:1:1:1:0:1:64:16384:MNWNNT:0:1:1
Ricoh Printer:1:1:1:255:1:255:1:1:255:1:0:255:1:8:255:1:1:1:0:1:>20:1:0:1:255:8192:M:N:N:N
Riverstone Metro Access Router:1:1:1:255:1:255:1:0:255:1:0:255:1:8:255:1:1:0:2:1:>20:1:1:1:64:17232:MNWNNT:0:1:1
SCO OpenServer 5.0.5:1:1:0:64:1:64:1:0:64:1:0:64:1:8:64:0:1:1:1:1:1:1:0:1:64:24820:M:N:N:N
SCO OpenServer 5.0.6:1:1:0:64:1:64:1:0:64:1:0:64:1:8:64:0:1:1:1:1:1:1:0:1:64:4380:M:N:N:N
SCO OpenServer 5.0.6:1:1:1:64:1:64:1:0:64:1:0:64:1:8:64:1:1:1:1:1:1:1:1:1:64:24820:M:N:N:N
SCO OpenServer 5.0.7:1:1:0:64:1:64:1:0:64:1:0:64:1:8:64:0:1:1:2:1:1:1:0:1:64:33580:M:N:N:N
SCO OpenServer 5:1:1:0:255:1:255:1:0:255:1:0:255:1:8:255:0:1:1:2:1:1:1:0:1:255:33580:M:N:N:N
SCO UnixWare 2.1.2:1:1:1:64:1:64:1:0:64:1:1:64:1:8:64:1:1:1:0:3:1:3:0:1:64:4096:M:N:N:N
SCO UnixWare 2.1.3:1:1:1:64:1:64:1:0:64:1:0:64:1:8:64:1:1:1:2:3:1:3:0:1:64:4096:M:N:N:N
SCO UnixWare 8.0:1:1:0:64:1:64:1:0:64:1:0:64:1:8:64:0:1:1:1:1:1:1:0:1:64:24820:MNWNNT:0:1:1
SMC TigerStack Switch:1:S:1:64:0:64:1:0:64:1:0:64:1:8:64:0:0:1:2:1:1:1:0:1:64:8192:MNWNNT:0:1:1
SNAP 3.4:1:1:1:255:0:255:1:0:255:1:0:255:1:8:255:1:1:0:0:3:1:3:0:1:32:16788:M:N:N:N
Sharp Copier Printer:1:1:1:64:0:64:1:0:64:1:0:64:1:64:64:0:1:1:1:1:1:1:0:1:64:2048:M:N:N:N
Sharp Copier Printer:1:1:1:64:0:64:1:0:64:1:0:64:1:>64:64:0:1:1:2:1:1:1:0:1:64:4096:M:N:N:N
Siemens PLC:0:1:0:64:1:64:1:0:64:1:1:64:1:8:64:0:1:2:2:1:1:1:0:1:64:560:M:N:N:N
Sipura Analog Telephone Adapter:1:1:0:255:0:255:1:0:255:1:0:255:1:8:255:0:1:1:2:1:1:1:0:1:255:16000:M:N:N:N
Slingbox:1:S:1:255:0:255:1:0:255:1:0:255:1:8:64:0:1:1:2:1:1:1:0:1:64:8192:M:N:N:N
SonicWall Firewall:1:1:1:64:0:64:1:0:64:1:0:64:1:8:64:1:1:0:0:1:1:1:0:1:64:8192:MNWNNT:0:1:1
SonicWall Firewall:1:1:1:64:0:64:1:0:64:1:0:64:1:8:64:1:1:0:0:3:1:3:0:1:64:8192:MNW:0:N:N
SonicWall Router:1:1:1:64:0:64:1:0:64:1:0:64:1:8:64:1:1:0:0:1:1:1:0:1:64:8192:MNW:0:N:N
Sony Contact PCS-1600:1:1:0:64:0:64:1:0:64:1:0:64:1:8:64:0:1:1:1:1:1:1:0:1:64:2144:M:N:N:N
Sony Network Camera SNC-RZ30N:1:1:0:255:0:255:1:0:255:1:0:255:1:8:255:0:1:1:1:1:1:1:0:1:64:8688:MNWNNSNNT:0:1:1
Sun RSC Card:1:1:1:64:1:64:1:0:64:1:0:64:1:8:64:1:1:0:0:1:1:1:0:1:64:8192:MNW:0:N:N
Sun Solaris 10:1:1:1:255:0:255:1:1:255:1:0:255:1:64:255:1:1:1:1:3:1:1:1:1:64:49232:NNTMNWNNS:0:1:1
Sun Solaris 10:1:1:1:255:0:255:1:1:255:1:0:255:1:64:255:1:1:1:2:1:1:1:1:1:64:49232:NNTMNWNNS:0:1:1
Sun Solaris 2.5:1:1:1:255:1:255:1:1:255:1:0:255:1:64:255:1:1:1:1:1:1:1:1:1:255:8760:M:N:N:N
Sun Solaris 2.6:0:1:1:255:1:255:1:1:255:1:0:255:1:64:255:1:1:1:2:1:1:1:1:1:255:10136:NNTNWM:0:1:1 
Sun Solaris 7:1:1:1:255:0:255:1:1:255:1:0:255:1:64:255:1:1:1:1:1:1:1:1:1:255:65160:NNTNWNNSM:0:1:1
Sun Solaris 7:1:1:1:255:0:255:1:1:255:1:0:255:1:64:255:1:1:1:1:1:1:1:1:1:64:33304:NNTMNWNNS:1:1:1
Sun Solaris 7:1:1:1:255:1:255:1:1:255:1:0:255:1:64:255:1:1:1:1:1:1:1:1:1:255:10136:NNTNWM:0:1:1
Sun Solaris 7:1:1:1:255:1:255:1:1:255:1:0:255:1:64:255:1:1:1:1:1:1:1:1:1:255:10136:NNTNWNNSM:0:1:1
Sun Solaris 7:1:1:1:255:1:255:1:1:255:1:0:255:1:64:255:1:1:1:1:3:1:1:1:1:255:10136:NNTNWNNSM:0:1:1
Sun Solaris 7:1:1:1:255:1:255:1:1:255:1:0:255:1:64:255:1:1:1:2:1:1:1:1:1:255:10136:NNTNWNNSM:0:1:1
Sun Solaris 8:1:1:1:128:0:128:1:1:128:1:0:128:1:64:128:1:1:1:1:3:1:1:1:1:128:24616:NNTNWNNSM:0:1:1
Sun Solaris 8:1:1:1:255:0:255:1:0:255:1:0:255:1:64:255:1:1:2:2:1:1:1:1:1:64:24624:NNTNWNNSM:0:1:1
Sun Solaris 8:0:1:1:255:1:255:1:1:255:1:0:255:1:64:255:1:1:1:2:1:1:1:1:1:64:24616:NNTNWNNSM:0:1:1
Sun Solaris 8:1:1:1:255:0:255:1:1:255:1:0:255:1:64:255:1:1:2:2:1:1:1:1:1:64:33304:NNTNWNNSM:0:1:1
Sun Solaris 8:1:1:1:255:0:255:1:0:255:1:0:255:1:8:64:1:1:1:1:1:1:1:1:1:64:24616:NNTNWNNSM:0:1:1
Sun Solaris 8:1:1:1:255:0:255:1:1:255:1:0:255:1:64:255:1:1:1:1:1:1:1:1:1:64:33304:NNTNWNNSM:0:1:1
Sun Solaris 8:1:1:1:255:0:255:1:1:255:1:0:255:1:64:255:1:1:1:1:3:1:1:1:1:64:24616:NNTNWNNSM:0:1:1
Sun Solaris 8:1:1:1:255:0:255:1:1:255:1:0:255:1:64:255:1:1:1:1:3:1:1:1:1:64:24624:NNTNWNNSM:0:1:1
Sun Solaris 8:1:1:1:255:0:255:1:1:255:1:0:255:1:64:255:1:1:1:1:3:1:1:1:1:64:33304:NNTNWNNSM:1:1:1
Sun Solaris 8:1:1:1:255:0:255:1:1:255:1:0:255:1:64:255:1:1:1:2:1:1:1:1:1:64:24616:NNTNWNNSM:0:1:1
Sun Solaris 8:1:1:1:255:0:255:1:1:255:1:0:255:1:64:255:1:1:1:2:1:1:1:1:1:64:33304:NNTNWNNSM:1:1:1
Sun Solaris 8:1:1:1:255:1:255:1:1:255:1:0:255:1:64:255:1:1:1:1:1:1:1:1:1:64:17376:NNTNWNNSM:0:1:1
Sun Solaris 8:1:1:1:255:1:255:1:1:255:1:0:255:1:64:255:1:1:1:1:1:1:1:1:1:64:24616:NNTNWNNSM:0:1:1
Sun Solaris 8:1:1:1:255:1:255:1:1:255:1:0:255:1:64:255:1:1:1:1:1:1:1:1:1:64:24624:NNTNWNNSM:0:1:1
Sun Solaris 8:1:1:1:255:1:255:1:1:255:1:0:255:1:64:255:1:1:1:1:1:1:1:1:1:64:65160:NNTNWNNSM:0:1:1
Sun Solaris 8:1:1:1:255:1:255:1:1:255:1:0:255:1:64:255:1:1:1:1:3:1:1:1:1:64:24616:NNTNWNNSM:0:1:1
Sun Solaris 8:1:1:1:255:1:255:1:1:255:1:0:255:1:64:255:1:1:1:2:1:1:1:1:1:64:24616:NNTNWNNSM:0:1:1
Sun Solaris 8:1:1:1:255:1:255:1:1:255:1:0:255:1:64:255:1:1:1:2:1:1:1:1:1:64:33304:NNTNWNNSM:1:1:1
Sun Solaris 9:1:1:1:255:0:255:1:0:255:1:0:255:1:64:255:1:1:1:2:1:1:1:1:1:64:49248:NNTMNWNNS:0:1:1
Sun Solaris 9:1:1:1:255:0:255:1:0:255:1:0:255:1:8:64:1:S:1:2:1:1:1:1:1:64:49232:NNTMNWNNS:0:1:1
Sun Solaris 9:1:1:1:255:0:255:1:1:255:1:0:255:1:64:255:1:1:1:1:1:1:1:1:1:64:49232:NNTMNWNNS:0:1:1
Sun Solaris 9:1:1:1:255:0:255:1:1:255:1:0:255:1:64:255:1:1:1:2:1:1:1:1:1:64:32832:NNTMNWNNS:0:1:1
Sun Solaris 9:1:1:1:255:0:255:1:1:255:1:0:255:1:64:255:1:1:1:2:1:1:1:1:1:64:49232:NNTMNWNNS:0:1:1
Sun Solaris 9:1:1:1:255:1:255:1:1:255:1:0:255:1:64:255:0:1:1:2:1:1:1:0:1:64:33304:NNTMNWNNS:1:1:1
Sun Solaris 9:1:1:1:255:1:255:1:1:255:1:0:255:1:64:255:1:1:1:1:1:1:1:1:1:64:33304:NNTMNWNNS:1:1:1
Sun Solaris 9:1:1:1:255:1:255:1:1:255:1:0:255:1:64:255:1:1:1:1:1:1:1:1:1:64:49232:NNTMNWNNS:0:1:1
Sun Solaris 9:1:1:1:255:1:255:1:1:255:1:0:255:1:64:255:1:1:1:1:3:1:1:1:1:64:49232:NNTMNWNNS:0:1:1
Sun Solaris 9:1:1:1:255:1:255:1:1:255:1:0:255:1:64:255:1:1:1:2:1:1:1:1:1:64:49232:NNTMNWNNS:0:1:1
Sun Solaris 9:1:1:1:255:1:255:1:1:255:1:0:255:1:64:255:1:1:1:2:1:1:1:1:1:64:49876:NNTMNWNNS:0:1:1
Sun Solaris 9:1:1:1:255:1:255:1:1:255:1:0:255:1:64:255:1:1:2:1:1:1:1:1:1:64:49248:NNTMNWNNS:0:1:1
Sun StorEdge Storage Array:1:1:1:255:1:255:1:1:255:1:1:255:1:8:255:1:1:1:0:1:1:1:0:1:64:4096:N:N:N:N
Sun T3+:1:1:1:255:1:255:1:1:255:1:1:255:1:8:255:1:1:1:0:1:1:1:0:1:64:4096:M:N:N:N
SunOS 4.1:1:1:1:255:1:255:1:1:255:1:1:255:1:8:255:1:1:1:2:1:1:1:0:1:64:4096:M:N:N:N
Symantec Enterprise Firewall:1:1:1:255:0:255:1:0:255:1:0:255:1:8:255:0:1:1:1:1:1:1:1:1:255:10136:NNTNWNNSM:0:1:1
Systech Serial Server:1:1:1:255:1:255:1:0:255:1:1:255:1:8:255:1:1:0:0:1:1:1:0:1:64:32768:M:N:N:N
Tandberg Television Device:0:1:0:64:1:64:1:1:64:1:1:64:1:8:64:0:1:2:2:1:1:1:0:1:64:4096:M:N:N:N
Tandberg Television Server:0:1:0:64:1:64:1:1:64:1:1:64:1:8:64:0:1:2:2:1:1:1:0:1:64:4096:M:N:N:N
Tandem:1:1:1:255:1:255:1:1:255:1:1:255:1:8:255:1:1:0:0:1:1:1:0:1:32:8192:MNWNNT:0:1:1
Tekronix Printer:1:1:0:128:0:128:1:0:128:1:0:128:1:8:128:0:1:1:1:1:1:1:0:1:128:2920:M:N:N:N 
TempTrax Digital Thermometer:1:1:0:64:0:64:1:0:64:1:0:64:1:8:64:0:1:1:1:1:1:1:0:1:64:0:M:N:N:N
Toshiba Digital PBX:0:1:0:255:0:255:1:0:255:1:0:255:1:8:255:0:1:1:2:1:1:1:0:1:255:4380:MS:N:N:N
Toshiba Digital Telephone PBX:0:1:0:255:0:255:1:0:255:1:0:255:1:8:255:0:1:1:1:1:1:1:0:1:255:4380:M:N:N:N
Tru64 Unix version 5.0:1:1:1:64:1:64:1:0:64:1:1:64:1:8:64:1:1:0:2:1:1:1:0:1:64:33580:MNW:0:N:N
Tru64 Unix version 5.1:0:1:1:64:1:64:1:0:64:1:1:64:1:8:64:1:1:1:2:1:1:1:0:1:128:61440:MNW:0:N:N
Tru64 Unix version 5.1:1:1:1:64:1:64:1:0:64:1:1:64:1:>64:64:1:1:1:1:1:1:1:0:1:128:61440:MNW:0:N:N
Tru64 Unix version 5.1:1:1:1:64:1:64:1:0:64:1:1:64:1:>64:64:1:1:1:2:1:1:1:0:1:64:61440:MNW:0:N:N 
Tru64 Unix version 5.1:1:1:1:64:1:64:1:1:64:1:1:64:1:8:64:1:1:1:1:1:1:1:0:1:128:61440:MNW:0:N:N
ULTRIX 4.4:1:1:0:255:1:255:1:1:255:1:1:255:1:8:255:0:1:0:0:3:1:3:0:1:64:16384:M:N:N:N
UNIX System V Release 4.0::1:1:1:255:1:255:1:1:255:1:0:255:1:64:255:1:1:1:1:1:1:1:1:1:64:49232:NNTNWNNSM:1:1:1
VMWare ESX Server 2.5:1:1:0:255:1:255:1:0:255:1:0:255:1:>64:255:0:1:1:2:1:1:1:1:0:64:5792:MSTNW:0:1:1
Vigor2600:1:1:0:255:0:255:1:0:255:1:0:255:1:8:255:0:1:1:1:1:1:1:0:1:255:2100:M:N:N:N
Vigor2600:1:1:0:255:0:255:1:0:255:1:0:255:1:8:255:0:1:2:1:1:1:1:0:1:255:2100:M:N:N:N
Vigor2600:1:1:0:255:0:255:1:0:255:1:0:255:1:8:255:0:1:2:2:1:1:1:0:1:255:2100:M:N:N:N
Vigor2600:1:1:0:255:0:255:1:0:255:1:0:255:1:8:255:0:1:1:2:1:1:1:0:1:255:2100:M:N:N:N
Visual Networks ASE 5.2:1:1:0:32:1:32:1:0:32:1:0:32:1:8:32:0:1:1:1:1:1:1:0:1:32:255:M:N:N:N
VxWorks 5.1:1:1:1:64:1:64:1:1:64:1:0:64:1:8:64:1:1:0:0:1:1:1:0:1:64:8192:MNW:0:N:N
VxWorks 5.4:1:1:1:64:1:64:1:0:64:1:0:64:1:8:64:1:1:0:0:1:1:1:0:1:64:8192:MNWNNT:0:1:1
VxWorks 5.4:1:1:1:64:1:64:1:0:64:1:0:64:1:8:64:1:1:0:0:3:1:3:0:1:64:8192:MNWNNT:0:1:1
VxWorks 5.5:1:1:1:64:1:64:1:0:64:1:0:64:1:64:64:1:1:0:2:1:1:1:1:1:64:16384:MNWNNT:0:1:1
Watchguard Firewall/VPN Appliance:1:S:0:64:0:64:1:0:64:1:0:64:1:8:64:0:S:1:2:1:1:1:0:S:64:5840:M:N:N:N
Xerox DocuColor:1:1:1:64:1:64:1:0:64:1:0:64:1:8:64:1:1:0:0:1:1:1:0:1:64:8192:M:N:N:N
Xerox Printer:1:1:1:255:1:255:1:0:255:1:0:255:1:8:255:1:1:0:0:3:>20:3:0:1:64:16384:M:N:N:N
Xerox Printer:1:1:1:255:1:255:1:1:255:1:1:255:1:8:255:1:1:0:0:3:1:3:0:1:32:4096:M:N:N:N
ZyXEL Router:1:1:0:255:0:255:1:0:255:1:0:255:1:8:255:0:1:2:2:1:1:1:0:1:255:23360:M:N:N:N
eComStation 1.1:1:S:1:64:0:64:1:0:64:1:0:64:1:8:64:0:S:1:2:1:1:1:1:1:64:33396:MNW:0:N:N
eComStation 1.2:1:1:1:64:1:64:1:1:64:1:0:64:1:8:64:1:1:0:0:3:1:3:0:1:64:33304:MNWNNT:0:1:1
";


function make_ttl(ttl)
{
 if ( ttl <= 32 )
	return 32;
else if ( ttl <= 64 )
return 64;
else if ( ttl <= 128 )
return 128;
else return 255;
}


function icmp_echo_probe()
{
id = rand() % 65534;
ip = forge_ip_packet(ip_v:4, ip_hl:5, ip_tos:6, ip_off:IP_DF,ip_len:20,
		ip_p:IPPROTO_ICMP, ip_id:0x4747, ip_ttl:0x40,
		ip_src:this_host());
icmp = forge_icmp_packet(ip:ip, icmp_type:8, icmp_code:123,
		    icmp_seq: id, icmp_id:id);

for ( i = 0 ; i < MAX_RETRIES ; i ++ )
{
filter = "icmp and src host " + get_host_ip() + " and icmp[0:1]=0 and icmp[6:2] = " + id;
reply = send_packet(icmp, pcap_active:TRUE, pcap_filter:filter, pcap_timeout:1);
if ( reply ) break;
}

if ( reply == NULL ) {  exit(0); }

sig = NULL;
code = get_icmp_element(icmp:reply, element:"icmp_code");

if ( code ) sig = ":1";
else sig = ":0";

ipid = get_ip_element(ip:reply, element:"ip_id");
if ( ipid == 0x4747 ) sig += ":S";
else if (ipid != 0) sig += ":1";
else sig += ":0";

tos = get_ip_element(ip:reply, element:"ip_tos");
#sig += ":[01]";
#if ( tos == 0 ) 
#sig += ":0";
#else 
#sig += ":1";

df_bit = get_ip_element(ip:reply, element:"ip_off");
if ( df_bit & IP_DF ) sig += ":1";
else sig += ":0";

ttl = make_ttl(ttl:get_ip_element(ip:reply, element:"ip_ttl"));

sig += ":" + ttl;

return sig;
}


function icmp_timestamp_probe()
{
 id = rand() % 65535;
ip = forge_ip_packet(ip_hl:5, ip_v:4,   ip_off:0,
	     ip_id:0x4343, ip_tos:0, ip_p : IPPROTO_ICMP,
	     ip_len : 20, ip_src : this_host(),
                     ip_ttl : 255);

 icmp = forge_icmp_packet(ip:ip,icmp_type : 13, icmp_code:0,
                          icmp_seq : 1, icmp_id : id);


 filter = "icmp and src host " + get_host_ip() + " and icmp[0:1] = 14 and icmp[4:2] = " + id;
 #display(filter, "\n");
 for ( i = 0 ; i < MAX_RETRIES ; i ++ )
   {
     reply = send_packet(icmp, pcap_active:TRUE, pcap_filter:filter, pcap_timeout:1);
     if ( reply ) break;
   }

 if ( reply == NULL ) 
 {
  sig = ":0:" + ttl + ":1";
  return sig;
 }
 
 sig = ":1";
 ttl = make_ttl(ttl:get_ip_element(ip:reply, element:"ip_ttl"));
 sig += ":" + ttl;

 ipid = get_ip_element(ip:reply, element:"ip_id");
 if ( ipid == 0x4343 ) { sig += ":S"; ip_id_sent = "S"; }
 else if (ipid != 0) { sig += ":1"; ip_id_sent = "1"; }
 else { sig += ":0"; ip_id_sent = "0"; }
 
 
 return sig;
}


function icmp_netmask_probe()
{
  id = rand() % 65535;
  ip = forge_ip_packet(ip_hl:5, ip_v:4,   ip_off:0,
                     ip_id:0x4444, ip_tos:0, ip_p : IPPROTO_ICMP,
                     ip_len : 20, ip_src : this_host(),
                     ip_ttl : 255);
  icmp = forge_icmp_packet(ip:ip,icmp_type : 17, icmp_code:0,
                          icmp_seq : 1, icmp_id : id, data:raw_string(0xFF, 0xFF, 0xFF, 0xFF));

 filter = "icmp and src host " + get_host_ip() + " and icmp[0:1] = 18 and icmp[4:2] = " + id;
 #display(filter, "\n");
 for ( i = 0 ; i < MAX_RETRIES ; i ++ )
   {
     reply = send_packet(icmp, pcap_active:TRUE, pcap_filter:filter, pcap_timeout:1);
     if ( reply ) break;
   }

 if ( reply == NULL ) 
 {
  sig = ":0:" + ttl + ":" + ip_id_sent;
  return sig;
 }
 
 sig = ":1";
 ttl = make_ttl(ttl:get_ip_element(ip:reply, element:"ip_ttl"));
 sig += ":" + ttl;

 ipid = get_ip_element(ip:reply, element:"ip_id");
 if ( ipid == 0x4444 ) { sig += ":S"; ip_id_sent = "S"; }
 else if (ipid != 0) { sig += ":1"; ip_id_sent = "1"; }
 else { sig += ":0"; ip_id_sent = "0"; }
 
 return sig;
}

function icmp_inforeq_probe()
{
  id = rand() % 65535;
  ip = forge_ip_packet(ip_hl:5, ip_v:4,   ip_off:0,
                     ip_id:0x4545, ip_tos:0, ip_p : IPPROTO_ICMP,
                     ip_len : 20, ip_src : this_host(),
                     ip_ttl : 255);
  icmp = forge_icmp_packet(ip:ip,icmp_type : 15, icmp_code:0,
                          icmp_seq : 1, icmp_id : id);

 filter = "icmp and src host " + get_host_ip() + " and icmp[0] = 16 and icmp[4:2] = " + id;
 #display(filter, "\n");
 for ( i = 0 ; i < MAX_RETRIES ; i ++ )
   {
     reply = send_packet(icmp, pcap_active:TRUE, pcap_filter:filter, pcap_timeout:1);
     if ( reply ) break;
   }

 if ( reply == NULL ) 
 {
  sig = ":0:" + ttl + ":" + ip_id_sent;
  return sig;
 }
 
 sig = ":1";
 ttl = make_ttl(ttl:get_ip_element(ip:reply, element:"ip_ttl"));
 sig += ":" + ttl;

 ipid = get_ip_element(ip:reply, element:"ip_id");
 if ( ipid == 0x4545 ) sig += ":S";
 else if (ipid != 0) sig += ":1";
 else sig += ":0";
 
 return sig;
}

function icmp_udpunreach_probe()
{
  local_var i;

  filter = "icmp[30:2] = 42000";
  for ( i = 1 ; i < MAX_RETRIES * 2 ; i ++ )
  {
    filter += " or icmp[30:2] = " + string(42000 + i);
  }

  sig = "";
 filter = "icmp and src host " + get_host_ip() + " and icmp[0] = 3 and (" + filter + ")";


 for ( i = 0 ; i < MAX_RETRIES * 2 ; i ++ )
   {
    ip = forge_ip_packet(ip_v   : 4, ip_hl  : 5, ip_tos : 0, ip_id  : 0x4664, ip_len : 20, ip_off : IP_DF, ip_p   : IPPROTO_UDP, ip_src : this_host(), ip_ttl : 255);
    ip = insstr(ip, raw_string(0x46, 0x64), 4, 5);
    udpip = forge_udp_packet( ip : ip, uh_sport : 53, uh_dport : 42000 + i, uh_ulen :8+128, uh_sum:0, data:crap(128));          
  reply = send_packet(udpip, pcap_active:TRUE, pcap_filter:filter, pcap_timeout:1);
     if ( reply ) break;
   }
 
 if ( ! reply ) 
 {
  return ":X:X:X:X:X:X:X:X:X:X";
 }

 hl  = get_ip_element(ip:reply, element:"ip_hl");
 len = get_ip_element(ip:reply, element:"ip_len");
 len -= hl * 4 + 8 + 20;

 # udp_echoed_dtsize

 if ( len == 8 ) sig = ":8";
 else if ( len <= 64 ) sig = ":64";
 else sig = ":>64";

 # reply_ttl 
 ttl = make_ttl(ttl:get_ip_element(ip:reply, element:"ip_ttl"));
 sig += ":" + ttl;

 # Precedence bits
 tos = get_ip_element(ip:reply, element:"ip_tos");
 #sig += ":[012]";
 #if ( tos == 0 ) sig += ":0";
 #else if ( tos == 0xc0 ) sig += ":2";
 #else sig += ":1";

 # Unfrag bit
 unfrag = get_ip_element(ip:reply, element:"ip_off");
 if ( unfrag & IP_DF ) sig += ":1";
 else sig += ":0";
 
 # IP ID
 ipid = get_ip_element(ip:reply, element:"ip_id");
 if ( ipid == 0x4664 || ipid == 0x6446) sig += ":S";
 else if (ipid != 0) sig += ":1";
 else sig += ":0";

 # Checksums
 udp = substr(reply, hl * 4 + 8 , strlen(reply) - 1);

 sum = substr(udp, 26, 27);
 udp2 = substr(udp, 20, 25) + raw_string(0,0) + substr(udp, 28, strlen(udp) - 1 );

 pseudo = substr(udp, 12, 19) + raw_string(0, 0x11) + htons(n:strlen(udp) - 20) + udp2;
 
 sum2 = ip_checksum(data:pseudo);
 origsum = substr(udpip, 26,27);
 if ( sum == raw_string(0,0) ) sig += ":0"; 
 else if ( sum == origsum || sum == sum2 ) sig += ":1";
 else sig += ":2";


 sum = get_ip_element(ip:udp, element:"ip_sum");
 udp2 = set_ip_elements(ip:udp, ip_sum:0);
 sum2 = get_ip_element(ip:udp2, element:"ip_sum");
 

 if ( sum == sum2 ) sig += ":1"; 
 else if ( sum == 0 ) sig += ":0";
 else sig += ":2";


 # echoed_ip_id
 ip_id = substr(udp, 4, 5);
 if ( hexstr(ip_id) == "4664" ) sig += ":1";
 else sig += ":3";

 # total_len
 len = get_ip_element(ip:udp, element:"ip_len");
 if ( len == 0x9c || len == 0x9c00 ) sig += ":1";
 else if ( len >= 20) sig += ":>20";
 else sig += ":<20";
 

 # 3bit_flag
 # ????
 off = substr(udp, 6, 7);
 if ( hexstr(off) == "4000" ) sig += ":1";
 else sig += ":3";
 

 return sig;
}


function tcp_synack_probe()
{
 local_var i,j, sport, pkt, tcp, ip;
 port = get_host_open_port();
 if ( ! port ) {  exit(0); }

 sport = rand() % 64000 + 1024;
 for ( i = 0 ; i < MAX_RETRIES ; i ++ )
 {
 ip = forge_ip_packet(   ip_v : 4,
                        ip_hl : 5,
                        ip_tos : 0x10,
                        ip_len : 20,
                        ip_id : 0x4747,
                        ip_p : IPPROTO_TCP,
                        ip_ttl : 255,
                        ip_off : IP_DF,
                        ip_src : this_host());



  opts = raw_string(2, 4, 1460 / 256, 1460 % 256 );
  opts += raw_string(4, 2);
  time = raw_string(1,2,3,4,5,6,7,8);
  opts += raw_string(8, 10) + time;
  opts += raw_string(1);
  opts += raw_string(3, 3, 0);
  seq   = rand();
  tcpip = forge_tcp_packet(  ip       : ip,
                             th_sport : sport,
                             th_dport : port,
                             th_flags : TH_SYN,
                             th_seq   : seq,
                             th_ack   : 0,
                             th_x2    : 0,
                             th_off   : (20+strlen(opts))/4,
                             th_win   : 5840,
                             th_urp   : 0, 
			     data     : opts);


     filter = "tcp and src host " + get_host_ip() + " and src port " + port + " and dst port " + sport + " and ( tcp[13:1] & " + string(TH_SYN|TH_ACK) + " == " + string(TH_SYN|TH_ACK) + " )";
     #display("filter=", filter, "\n");
     reply = send_packet(tcpip, pcap_active:TRUE, pcap_filter:filter, pcap_timeout:1);
     if ( strlen(reply) ) {
	if ( NASL_LEVEL >= 3000 )
	{
	  pkt = packet_split(reply);
	  if ( pkt == NULL ) continue;
	  ip  = pkt[0];
	  ip  = ip["data"];
	  tcp = pkt[1];
	  tcp = tcp["data"];
	  flag = tcp["th_flags"];
	}
	else 
	   flag = get_tcp_element(tcp:reply, element:"th_flags");
	break;	
	}
   }
 
 if ( flag & (TH_SYN|TH_ACK) != TH_SYN|TH_ACK) exit(0);
 if ( strlen( reply ) == 0 ) { exit(0); }
 
 
 if ( NASL_LEVEL < 3000 )
  tos = get_ip_element(ip:reply, element:"ip_tos");
 else
  tos = ip["ip_tos"];
 #sig = ":[^:]*"; 
 sig = "";
 #if ( tos == 0 ) sig = ":0";
 #else sig = ":" + hex(tos);


 if ( NASL_LEVEL < 3000 )
  df = get_ip_element(ip:reply, element:"ip_off");
 else
  df = ip["ip_off"];

 if ( df & IP_DF ) sig += ":1";
 else sig += ":0";

 
 if ( NASL_LEVEL < 3000 )
  ipid = get_ip_element(ip:reply, element:"ip_id");
 else
  ipid = ip["ip_id"];

 if ( ipid == 0x4747 ) sig += ":S";
 else if (ipid != 0) sig += ":1";
 else sig += ":0";

 ttl = make_ttl(ttl:get_ip_element(ip:reply, element:"ip_ttl"));
 sig += ":" + ttl;

 if ( NASL_LEVEL < 3000 )
  win = get_tcp_element(tcp:reply, element:"th_win");
 else
  win = tcp["th_win"];

 sig += ":" + win;
 
 if ( NASL_LEVEL < 3000 )
  hl = get_ip_element(ip:reply, element:"ip_hl");
 else
  hl = ip["ip_hl"];

 if ( NASL_LEVEL < 3000 )
  th_off = get_tcp_element(tcp:reply, element:"th_off");
 else
  th_off = tcp["th_off"];

 tcpopts = substr(reply, hl * 4 + 20, (hl * th_off) * 4 - 1);
 
 str = "";
 blank = "";
 for ( i = 0 ; i < strlen(tcpopts); i ++ )
 {
  if ( isnull(tcpopts[i]) ) break;
  if ( ord(tcpopts[i]) == 2 ) str +=  "M";
  else if ( ord(tcpopts[i]) == 1 ) str += "N";
  else if ( ord(tcpopts[i]) == 4 ) str += "S";
  else if ( ord(tcpopts[i]) == 3 ) { 
	str += "W";
	if ( isnull(tcpopts[i+2]))break;
	wscale = ord(tcpopts[i+2]);
	}
  else if ( ord(tcpopts[i]) == 8 ) {
	str += "T";
	tsval = substr(tcpopts, i + 2, i + 6 );
        tsecr = substr(tcpopts, i + 6, i + 9);
      }
   else if (ord(tcpopts[i]) == 0 ) {  break; }

  if ( ord(tcpopts[i]) != 1 ) {
	 if ( isnull(ord(tcpopts[i+1]))) break;
	 j = ord(tcpopts[i+1]) - 1;
	 if ( j >= 0 ) i += j;
	}
 }
 
 sig += ":" + str;

 if ( !isnull(wscale) )
 {
  sig += ":" + wscale;
 }
 else sig += ":N";

 if ( tsval )
 {
 if( hexstr(tsval) >< "0000000000" ) sig += ":0";
 else sig += ":1";
 }
 else sig += ":N";
 
 if ( tsecr )
 {
 if( hexstr(tsecr) >< "0000000000" ) sig += ":0";
 else sig += ":1";
 }
 else sig += ":N";
 
  
 return sig;
}

#-------------------------------------------------------------------------------------------------#
# DCOM_RECV											  							  				  #
#-------------------------------------------------------------------------------------------------#
function dcom_recv(socket)
{
 local_var buf, len;
 
 buf = recv(socket:socket, length:9);
 if(strlen(buf) != 9)return NULL;
 
 len = ord(buf[8]);
 buf += recv(socket:socket, length:len - 9);
 return buf;
}

#-------------------------------------------------------------------------------------------------#
# CHECK_WINOS 	- KK Liu	
# Updated 8/25/2004	- check kb first for WinOS identification		  							  #
# Updated 11/04/2004- add XP sp2 identification						  							  #
#-------------------------------------------------------------------------------------------------#
function check_winos()
{
    kb = get_kb_item("Host/OS/smb");
    if ( kb ) 
    {
       name = NULL;
       if ("Windows 4.0" >< kb  ) { flag = 0; name = "Microsoft Windows NT 4.0"; }
       if ("Windows 5.0" >< kb  ) { flag = 0; name = "Microsoft Windows 2000"; }
       if ("Windows 5.0 Server" >< kb  ) { flag = 0; name = "Microsoft Windows 2000 Server"; }
       if ("Windows 5.1" >< kb  ) { 
         	if (check_XP_SP2() == 1) name = "Microsoft Windows XP SP2";
        	else name = "Microsoft Windows XP";  
       		flag = 0;
       }
       if ("Windows 5.2" >< kb || "Windows Server 2003" >< kb ) { flag = 0; name = "Microsoft Windows 2003 Server"; }
       if ( egrep(pattern:"Windows.*Code Name.*Longhorn", string:kb)  ) { flag = 0; name = "Microsoft Windows Vista (beta)"; }

		if ( name ) 
		{
				report = "The remote host is running " + name;
				set_kb_item(name:"Host/OS/icmp", value:name);
				security_note(port:0, data: report );
				exit(0);
		}
    }

	# SMB failed to id the OS, attempt RPC 
	port = 135;
	chk = raw_string (0x02,0x00,0x01,0x00);

	bindwinme = raw_string(
	0x05,0x00,0x0b,0x03,0x10,0x00,0x00,0x00,0x48,0x00,0x00,0x00,0x53,0x53,0x56,0x41,
	0xd0,0x16,0xd0,0x16,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x01,0x00,
	0xe6,0x73,0x0c,0xe6,0xf9,0x88,0xcf,0x11,0x9a,0xf1,0x00,0x20,0xaf,0x6e,0x72,0xf4,
	0x02,0x00,0x00,0x00,0x04,0x5d,0x88,0x8a,0xeb,0x1c,0xc9,0x11,0x9f,0xe8,0x08,0x00,
	0x2b,0x10,0x48,0x60,0x02,0x00,0x00,0x00
	);


	if ( get_port_state(port) )
	{
    	soc = open_sock_tcp(port);
	if(soc)
	{
	    send(socket:soc,data:bindwinme);
        rwinme  = dcom_recv(socket:soc);
        if(!strlen(rwinme))return;
	    lenwinme = strlen(rwinme);
	    stubwinme = substr(rwinme, lenwinme-24, lenwinme-21);
	    if (debug)
	    {
	    	display('len = ', lenwinme, '\n');
			display('stub  = ', hexstr(stubwinme), '\n');
			display('r = ', hexstr(rwinme), '\n');
	    }
	    if (stubwinme >< chk)
	    {
		return 0; # Conflicts with HP/UX...
	    	version = "Microsoft Windows 95/98/ME";
	    	if (debug) display(version,'\n');
			report = "The remote host is running " + version;
			set_kb_item(name:"Host/OS/icmp", value:version);
			security_note(port:0, data: report );
			close(soc);
			exit(0);
           }
	    check_NT2K(soc:soc);
	}
	}


}

#-------------------------------------------------------------------------------------------------#
# IS_SERVER	- KK Liu
#-------------------------------------------------------------------------------------------------#
function is_Server()
{
	SRVchk = raw_string (0xFD,0xF3);
	multiplex_id = rand();
	g_mhi = multiplex_id / 256;
	g_mlo = multiplex_id % 256;
	port = 445;
	neg_prot = raw_string
	   	(
		 0x00, 0x00, 0x00, 0xA4, 0xFF, 0x53,
		 0x4D, 0x42, 0x72, 0x00, 0x00, 0x00, 0x00, 0x08,
		 0x01, 0xC8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		 0x40, 0x06, 0x00, 0x00, g_mlo, g_mhi, 0x00, 0x81,
		 0x00, 0x02
		 ) + "PC NETWORK PROGRAM 1.0" + raw_string(0x00, 0x02) +
		 "MICROSOFT NETWORKS 1.03" + raw_string(0x00, 0x02) + 
		 "MICROSOFT NETWORKS 3.0"  + raw_string(0x00, 0x02) + 
		 "LANMAN1.0" + raw_string(0x00, 0x02) + 
		 "LM1.2X002" + raw_string(0x00, 0x02) + 
		 "Samba" +     raw_string(0x00, 0x02) +
		 "NT LANMAN 1.0" + raw_string(0x00, 0x02) +
		 "NT LM 0.12" + raw_string(0x00);

	if (debug) display('Server check .....\n');
        soc = open_sock_tcp(port);
	if(soc)
	{
		send(socket:soc, data:neg_prot);
		r = smb_recv(socket:soc, length:4000);
		if(strlen(r) < 38)return(NULL);

        if(!strlen(r))return 0;
       	stub = substr(r, 56, 57);
       	if (debug)
	    {
			display('stub  = ', hexstr(stub), '\n');
			display('r = ', hexstr(r), '\n');
	    }

       	if (stub >< SRVchk) # check XP vs. 2003
       	{ 
	    	close(soc);
	    	return (1);
	    }
	}
	return (0);
}

#-------------------------------------------------------------------------------------------------#
# CHECK_NT2K - KK Liu											  							      #
# Updated 11/04/2004- add XP sp2 identification						  							  #
#-------------------------------------------------------------------------------------------------#
function check_NT2K(soc)
{
	XPchk = raw_string (0x00,0x00,0x00,0x00);
	
	NT2Ktest = raw_string( 
	0x05, 0x00, 0x0b, 0x03, 0x10, 0x00, 0x00, 0x00,
	0xcc, 0x00, 0x00, 0x00, 0x84, 0x67, 0xbe, 0x18,
	0x31, 0x14, 0x5c, 0x16, 0x00, 0x00, 0x00, 0x00,
	0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00,
	0xb8, 0x4a, 0x9f, 0x4d, 0x1c, 0x7d, 0xcf, 0x11,
	0x86, 0x1e, 0x00, 0x20, 0xaf, 0x6e, 0x7c, 0x57,
	0x00, 0x00, 0x00, 0x00, 0x04, 0x5d, 0x88, 0x8a,
	0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00,
	0x2b, 0x10, 0x48, 0x60, 0x02, 0x00, 0x00, 0x00,
	0x02, 0x00, 0x01, 0x00, 0xa0, 0x01, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x46, 0x00, 0x00, 0x00, 0x00,
	0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11,
	0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60,
	0x02, 0x00, 0x00, 0x00, 0x03, 0x00, 0x01, 0x00,
	0x0a, 0x42, 0x24, 0x0a, 0x00, 0x17, 0x21, 0x41,
	0x2e, 0x48, 0x01, 0x1d, 0x13, 0x0b, 0x04, 0x4d,
	0x00, 0x00, 0x00, 0x00, 0x04, 0x5d, 0x88, 0x8a,
	0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00,
	0x2b, 0x10, 0x48, 0x60, 0x02, 0x00, 0x00, 0x00,
	0x04, 0x00, 0x01, 0x00, 0xb0, 0x01, 0x52, 0x97,
	0xca, 0x59, 0xcf, 0x11, 0xa8, 0xd5, 0x00, 0xa0,
	0xc9, 0x0d, 0x80, 0x51, 0x00, 0x00, 0x00, 0x00,
	0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11,
	0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60,
	0x02, 0x00, 0x00, 0x00);

	if (debug) display('NT 2K check -----\n');

	    send(socket:soc,data:NT2Ktest);
        r  = dcom_recv(socket:soc);
        if(!strlen(r))return 0;
             
	    len = strlen(r);
       	if (debug)
	    {
	    	display('len = ', len, '\n');
			display('r = ', hexstr(r), '\n');
	    }
	    
	    if (len == 132)
	    {
	    	version = "Microsoft Windows NT 4.0";
	    	if (debug) display(version,'\n');
			report = "The remote host is running " + version;
			set_kb_item(name:"Host/OS/icmp", value:version);
			security_note(port:0, data: report );
	    		exit(0);
        }
        else
        {
        	stub = substr(r, 20, 23);
	       	if (debug)
		    {
		    	display('len = ', len, '\n');
				display('stub = ', hexstr(stub), '\n');
		    }
        	
        	if (stub >< XPchk) # check if XP, 2003
        	{
        		if (is_Server()==1) version = "Microsoft Windows 2003";
        		else {
        			if (check_XP_SP2() == 1) version = "Microsoft Windows XP SP2";
        			else version = "Microsoft Windows XP";  
        			
        		}    		
        	}
        	# identify Win2K server vs. workstation
        	else 
        	{
        		if (is_Server()==1) version = "Microsoft Windows 2000 Server";
        		else version = "Microsoft Windows 2000 Professional";
        	}
	    	if (debug) display(version,'\n');
			report = "The remote host is running " + version;
			set_kb_item(name:"Host/OS/icmp", value:version);
			security_note(port:0, data: report );       	 	
	    		exit(0);
        }
	    close(soc);
}

#-------------------------------------------------------------------------------------------------#
# CHECK_XP_SP2 - KK Liu 2004-11-05											  							      #
#-------------------------------------------------------------------------------------------------#
function check_XP_SP2()
{
	#debug = 1;
	port = 135;
	sp2chk = raw_string(0x05,0x00,0x00,0x00,0x00,0x00,0x00,0x00);
	acceptance = raw_string(0x00,0x00);
	
	bind = raw_string (
	0x05,0x00,0x0b,0x03,0x10,0x00,0x00,0x00,0x48,0x00,0x00,0x00,0x01,0x00,0x00,0x00,
	0xd0,0x16,0xd0,0x16,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x01,0x00,
	0x08,0x83,0xaf,0xe1,0x1f,0x5d,0xc9,0x11,0x91,0xa4,0x08,0x00,0x2b,0x14,0xa0,0xfa,
	0x03,0x00,0x00,0x00,0x04,0x5d,0x88,0x8a,0xeb,0x1c,0xc9,0x11,0x9f,0xe8,0x08,0x00,
	0x2b,0x10,0x48,0x60,0x02,0x00,0x00,0x00	
	);
	
	
	EPquery = raw_string( 
	0x05,0x00,0x00,0x03,0x10,0x00,0x00,0x00,0x64,0x00,0x00,0x00,0x01,0x00,0x00,0x00,
	0x4c,0x00,0x00,0x00,0x00,0x00,0x02,0x00,
	0x03,0x00,0x00,0x00, 
	0x01,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x02,0x00,0x00,0x00,
	0x78,0x57,0x34,0x12,0x34,0x12,0xcd,0xab,0xef,0x00,0x01,0x23,0x45,0x67,0x89,0xac, 
	0x73,0x2b,0x40,0x00,
	0x01,0x00,0x00,0x00, 
	0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x01,0x00,0x00,0x00
);

	if (debug) display('XP sp2 check -----\n');

	if ( get_port_state(port) )
	{
    	soc = open_sock_tcp(port);
		if(soc)
		{
	
		    send(socket:soc,data:bind);
	        r  = dcom_recv(socket:soc);
	        if(!strlen(r)) return(0);
	        #check if acceptance
		    len = strlen(r);
        	stub = substr(r, len-24, len-23);
        	if (stub >!< acceptance) # check if SP2
        	{     		
        		return (0);     		
        	}
        	
        	        	    
	       	if (debug)
		    {
		    	len = strlen(r);
		    	display('len = ', len, '\n');
				display('r = ', hexstr(r), '\n');
		    }
		    
		    send(socket:soc,data:EPquery);
	        r  = dcom_recv(socket:soc);
	        if(!strlen(r)) return(0);
		close(soc);
	        
	        len = strlen(r);
        	stub = substr(r, len-8, len-1);
	       	if (debug)
		    {
		    	display('len = ', len, '\n');
				display('stub = ', hexstr(stub), '\n');
		    }
        	
        	if (stub >< sp2chk) # check if SP2
        	{     		
        		return (1); # SP2     		
        	}
      	 	
		}
	}
	return(0);
}

#-------------------------------------------------------------------------------------------------#
# MAIN 												  #
#-------------------------------------------------------------------------------------------------#

if ( islocalhost() ) exit(0);

# check windows os using RPC + neg - by KK Liu
check_winos();

mysig = icmp_echo_probe() + icmp_timestamp_probe() + icmp_netmask_probe() + icmp_inforeq_probe() + icmp_udpunreach_probe() + tcp_synack_probe();

set_kb_item(name:"Host/OS/fingerprint", value:mysig);






os = egrep(pattern:mysig, string:db);


if ( os )
{
 os = split(os);
 name = "";
 flag = 0;
 foreach os_name (os)
 {
 tmp = split(os_name, sep:":", keep:0);
 if ( strlen(name) == 0 )
	name = tmp[0];
 else
	{
	name += '\n' + tmp[0];
	flag ++;
	}
 }

 if ( strlen ( name ) ) 
 {

  if ( egrep(pattern:".*Windows.*", string:name) )
  {
  }
 if ( ! flag ) 
	report = "The remote host is running " + name;
 else 
	report = "The remote host is running one of these operating systems : " + '\n' + name;


 set_kb_item(name:"Host/OS/icmp", value:name);

 security_note(port:0, data:report);
 exit(0);
 }
}

if( "X:X:X:X:X:X" >< mysig) count_similarities ++;

results = split(mysig, sep:":", keep:0);
db = egrep(pattern:"^[^#].*", string:db);

foreach sig (split(db))
{
 sig = sig - '\n';
 if ( strlen(sig) > 1 )
 {
 v = split(sig, sep:":", keep:0);
 n = max_index(v);
 os = v[0];
 diff = 0;
 sim  = 0;
 window = 0;
 for ( i = 1; i < n ; i ++ )
   {
   if ( v[i] != results[i] && ( count_similarities == 0 || results[i] != 'X')  ) diff ++;
   else if ( v[i] == results[i] && results[i] != 'X' ) sim ++;
   if ( i == 26 ) window ++;
   }

 differences[os] = diff;
 similarities[os] = sim;
 windows[os] = window;
 
 }
}

m = 999999;
n = -1;
foreach d (differences)  if ( d < m ) m = d;
foreach s (similarities) if ( s > n ) n = s;


if (  count_similarities  )
{
 if ( n > 12 )
 {
 os = NULL;
 count = 0;
  foreach i (sort(keys(similarities)))
  {
   if ( similarities[i] == n )
    {
     if( ! os ) { os = i; count = 1; }
     else { os += '\n' + i; count ++ ; }
    }
  }

  if ( count == 1 && n > 20 )
  {
	report = "The remote host is running " + os;
 	security_note(port:0, data:report);
 	set_kb_item(name:"Host/OS/icmp", value:os);
	exit(0);
  }
  else if ( os ) 
  {
report = 'Nessus was not able to reliably identify the remote operating system. It might be:\n' + os;
  security_note(port:0, data:report);
  }

 }
 exit(0);
}

if ( m < 10 )
{

os = NULL;
count = 0;

foreach i (sort(keys(differences)))
{
 if ( differences[i] == m )
  {
   if( ! os ) { os = i; count = 1; }
   else { os += '\n' + i; count ++ ; }
  }
}

if ( count == 1 && m == 1 && windows[os] == 1)
{
	report = "The remote host is running " + os;
 	security_note(port:0, data:report);
 	set_kb_item(name:"Host/OS/icmp", value:os);
	exit(0);
}

report = 'Nessus was not able to reliably identify the remote operating system. It might be:\n' + 
 os + '\nThe fingerprint differs from these known signatures on ' + m + ' points.\n' +
 'If you know what operating system this host is running, please send this signature to\n' +
 'os-signatures@nessus.org : \n' + mysig + '\n($Revision: 1.138 $)';

 security_note(port:0, data:report);
 exit(0);
}




report = "The remote host operating system could not be identified. If you know what this server
is running please send this signature to os-signatures@nessus.org : 
" + mysig + "
($Revision: 1.138 $)";
security_note(port:0, data:report);
