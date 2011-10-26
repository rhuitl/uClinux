#
# **** THIS SCRIPT IS EXPERIMENTAL! ****
#
# (C) 2003 Michel Arboi <mikhail@nessus.org>
#
# Redistribution and use in source, with or without modification, are 
# permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. All advertising materials mentioning features or use of this software
#    must display the following acknowledgement:
#     This product includes software developed and data gathered by 
#     Michel Arboi
#
# This script is not a transcription in NASL of HMAP, which is much 
# more complex. It is only based upon ideas that are described in 
# Dustin Lee's thesis:
# HMAP: A Technique and Tool For Remote Identification of HTTP Servers
#
# To receive useful contributions, we have to generate a significant 
# signature for unknown servers. This signature should be compact, 
# so only the most significant tests should be selected. An interesting 
# side effect is that the plugin will be quicker!
# As I don't have enough web servers, versions, sub-versions, and strange
# or typical configurations, I run into a chicken & egg problem:
# so we must keep in mind that the test set may change, and the known
# signatures will have to be adapted, or recomputed.
#
# NOTE TO SIGNATURE CONTRIBUTORS
# If you have different servers that return the _same_ signature, this 
# means that the test has to be enhanced. Please download hmap from
# http://ujeni.murkyroc.com/hmap/ and runs it against your servers, and
# send us the generated files.
#
# To look for duplicated signatures, run:
# egrep '^(...:){20,}' www_fingerprinting_hmap.nasl | awk -F: '{print $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25; }' | sort | uniq -d
#
# Signature contributors: 
# Chava Alvarez, Greg Armer, Rafael Ausejo Prieto, Alex Bartl, Jochen Bartl, 
# Pascal Béderède, Bob T. Berge, Luca Bigliardi, 
# Henk Bokhoven, Wayne Boline, 
# Andrew Brampton, J Barger, Jorge Blat, Randy Bias, Paul Bowsher,
# Dustin Butler, Niels Büttner, Jesús Manuel Carretero,
# James Chenvert, Joe Clifton, Russ Cohen, 
# Lionel Cons, Owen Crow, Kevin Davidson, Stephen Davies, Chuck Deal,
# Renaud Deraison, 
# Peters Devon, Sean Dreilinger, Shaun Drutar, Franck Dubray, 
# Thierry Dussuet, 
# Daniel C. Endrizzi, Aizat Faiz, Joshua Fielden, Tomasz Finke, 
# Stephen Flanagan, Dennis Freise, Scott Fringer, Raul Gereanu, Chad Glidden, 
# Volker Goller, Thomas Graham, Rick Gray, Matthew Gream, Daniel Griswold, 
# Gary Gunderson, Tim Hadlow, Stuart Halliday,
# Tomi Hanninen, 
# Chris Hanson, Chris Harrington, Maarten Hartsuijker, Greg Hartwig, 
# James Haworth, Jeffrey G Heller, Rolando Hernandez, John Hester, 
# John T Hoffoss, Florian Huber, Thomas Hunter, Fabien Illide, Ron Jackson,
# Jay Jacobson,
# Simen Graff Jenssen, Bill Johnson, Paul Johnston, 
# Maciek Jonakowski, Michiel Kalkman, 
# Imre Kálóczi, Pavel Kankovsky, Boris Karnaukh, Egon Kastelijn, 
# Eddie Kilgore, Don M. Kitchen, Yuval Kogman,
# Robert Kolaczynski, Michael Kohne, Pierre Kroma, Nerijus Krukauskas, 
# Paul Kurczaba, David Kyger, Andre Lewis, Tarmo Lindström, 
# Sébastien Louafi, Mark Lowe, Richard Lowe, Stéphane Lu,
# Martin Maèok, Florin Mariuteac, Raul Mateos Martin, 
# Mats Martinsson, Thomas Maurer, Zul Mohd, Mick Montgomery, Greg Mooney,
# Jose Manuel Rodriguez Moreno, Mike Nelson, Kevin O'Brien, 
# Warren Overholt, C. Paparelli, Eric F Paul, Ashesh Patel, Marc Pinnell,
# Nicolas Pouvesle,
# Federico Petronio, John Pignata, Abri du Plooy, Xavier Poli, Dave Potts, 
# Matthew Pour, Mike Pursifull,
# Jason Radley, Jim Rather, Dmytro O. Redchuk, Mark Rees, 
# Thomas Reinke, Cas Renooij, Jon Repaci, Ruben Rickard,
# Iben Rodriguez, Brooks Rosenow, 
# Mark Sayer, Michael Scheidell, Frank Schreiner, Don Senzig, 
# Beat Siegenthaler, Barn Ski, Adam Smith, Marco Spoel, Ricardo Stella, 
# Andrä Steiner, Iain Stirling, 
# Marius Strom, Robby Tanner, George A. Theall, Adam Thompson, 
# Ralph Utz, Mattias Webjorn Eriksson, Mikael Westerlund, Jeremy Wood, 
# Bruce Wright, 
# Jeffrey Yu, Paolo Zavalloni, Thorsten Zenker, 
# Andrew Ziem, 
# Asmodianx, Crowley, Daniel, Empire Strikes Back, Ffoeg, The Frumster, 
# Joe pr, mjnsecurity, 
# Munkhbayar, Neo, Noisex, Pavel, Podo, PoiS QueM, Silencer, Stephan, 
# Sullo, Vitaly, Yanli-721, Yong, Zube
#
# If I forgot you in this list or mispelled your name (or nym), please tell me!
# 

# Unused / unknown / imprecise signatures:
# ---:200:405:---:---:---:---:VER:---:200:---:---:200:---:---:---:---:+++:400:405:405:405:405:405:+++:^$:[EMC]

if (description)
{
  script_version("$Revision: 1.386 $");
  script_id(11919);
#  script_cve_id("CVE-MAP-NOMATCH");
  name["english"] = "HMAP";
  script_name(english:name["english"]);

  desc["english"] = "
This script tries to identify the HTTP Server type and version by
sending more or less incorrect requests.

An attacker may use this to identify the kind of the remote web server
and gain further knowledge about this host.

Suggestions for defense against fingerprinting are presented in
http://acsac.org/2002/abstracts/96.html

See also :	http://ujeni.murkyroc.com/hmap/
		http://seclab.cs.ucdavis.edu/papers/hmap-thesis.pdf
		
Risk factor : Low";

  script_description(english:desc["english"]);
 
  summary["english"] = "Fingerprints the web server";
  script_summary(english:summary["english"]);
 
  script_category(ACT_MIXED_ATTACK);
 
  script_copyright(english:"This script is Copyright (C) 2003 Michel Arboi - HMAP research by Dustin Lee");
  family["english"] = "General";
  script_family(english:family["english"]);
  # Maybe I should add a timeout: this script can be very slow against
  # some servers (4m20s against u-server-0.x)
  script_dependencie("find_service.nes", "http_login.nasl", "httpver.nasl", "no404.nasl");
  script_require_ports("Services/www", 80);
  exit(0);
}

# MA 2005-06-24: I need to extract a simplified version from this script.
# Less requests, and less precise banners.
include("global_settings.inc");
if (! experimental_scripts && ! thorough_tests)
{
 log_print('www_fingerprinting_hmap only runs in "experimental" or "thorough" modes\n');
 exit(0);
}


#### Fingerprints
# The last field is the name of the server, the previous field is the regex
# that the "Server" field is supposed to match.
# If the regex field is empty, the last field MUST be equal to the banner
#
# +++ is a joker than matches anything (useful when we add requests)
# --- means no answer
# HTM means that the server returned HTML directly, without any clean HTTP 
# answer code & headers.
# VER means that the server answered with an invalid HTTP version, e.g.:
#    HTTP/3.14 
#    HTTP/1.X 
#    HTTP/
#    http/1.0
# Note that this last code was added recently, and that previous signature
# may contain xxx instead in 4th, 5th, 6th or 8th position, or a valid 
# numeric code only in 6th or 8th position in some rare cases (when the 
# server answered with HTTP/ or http/1.0 in lower case) 
#

fingerprints = "
xxx:302:200:505:400:400:400:302:400:302:400:400:302:400:400:400:400:404:404:404:404:200:404:404:+++::2Wire-Gateway/Shasta
200:200:404:200:200:200:404:200:200:404:404:404:200:404:404:404:200:404:404:404:404:404:404:404:+++:^$:One port print server (GP-100P) by ConnectGear
# The switch was running OS version 3.21, hardware version 07.01.01, Boot Version 2.21
200:200:400:200:200:200:200:400:200:400:400:400:200:200:200:200:200:200:200:200:400:400:400:400:+++::3Com/v1.0 [SuperStack 3 Switch 4400 (3C17204)]
# There are two Abyss web server...
# from abyss.sourceforge.net
200:200:400:505:400:400:500:400:400:200:500:500:200:400:400:400:200:405:405:405:200:405:405:405:400::ABYSS/0.3
# Abyss/1.2.1.0 (Linux) AbyssLib/1.0.7 # from www.aprelium.com
# Abyss/1.2.3.0-Win32 AbyssLib/1.1.0
HTM:200:HTM:505:HTM:HTM:HTM:HTM:HTM:200:HTM:HTM:200:HTM:HTM:HTM:200:404:404:404:404:404:404:404:200:^Abyss/1\.2\.[1-3]\.:Abyss/1.2.1.0-3 (Linux/Win32)
HTM:200:HTM:505:HTM:HTM:HTM:HTM:HTM:200:HTM:HTM:200:HTM:HTM:HTM:200:302:302:302:302:302:302:302:200::Abyss/1.1.6 (Win32) AbyssLib/1.0.7
HTM:200:---:---:---:---:---:---:---:200:---:---:200:---:---:---:200:404:404:404:404:404:404:404:200::Abyss/2.0.6-X1-Win32 AbyssLib/2.0.6
HTM:200:400:VER:VER:VER:---:VER:xxx:200:---:---:200:400:400:501:400:+++:404:404:404:404:404:404:+++::Acme.Serve/v1.7 of 13nov96
200:200:---:200:200:200:200:---:200:200:200:200:200:200:200:+++:200:404:---:---:---:---:---:---:+++::ADSM_HTTP/0.1
200:200:400:200:200:200:400:200:200:400:400:400:200:200:403:400:200:+++:501:400:400:400:400:400:+++::Agent-ListenServer-HttpSvr/1.0
200:200:400:200:200:200:400:200:200:400:400:400:200:200:200:200:200:+++:400:400:400:400:400:400:+++:: McAfee-Agent-HttpSvr/1.0
200:200:400:200:200:200:400:200:200:400:400:400:200:200:200:200:200:501:501:400:400:400:400:400:+++:^Agent-ListenServer-HttpSvr/1\.0$:McAfee ePolicy Orchestrator Agent version 3.1.0.211
200:200:400:200:200:200:400:200:200:400:400:400:200:200:200:400:200:501:501:400:400:400:400:400:400:^Agent-ListenServer-HttpSvr/1\.0$:McAfee ePolicy Orchestrator Agent version 3
# mCAT(TM) is an realtime operating system for use in embedded system.
# It is a original design of mocom software GmbH & Co KG, Aachen,
# Germany. mCAT supports ARM-Plattforms.
400:200:501:200:200:400:400:501:400:200:501:400:---:200:200:501:200:404:501:501:501:501:501:501:+++::mCAT-Embedded-HTTPD
# hardware device (Allegro-Software-RomPager) embedded in an APC UPS controller card
# http://archives.neohapsis.com/archives/ntbugtraq/2000-q2/0223.html
200:200:200:200:400:200:405:405:400:405:405:405:200:404:404:+++:---:---:405:405:404:---:---:405:+++::Allegro-Software-RomPager/ 2.10
#
200:200:404:400:400:400:400:400:400:400:400:400:200:400:404:404:200:404:404:404:404:404:400:400:400:^AllegroServe/1\.2\.[34]:AllegroServe/1.2.37 to 1.2.42
# APC Web/SNMP Management Card 
# (MB:v3.3.2 PF:v1.1.0 PN:apc_hw02_aos_110.bin AF1:v1.1.1 AN1:apc_hw02_sumx_111.bin MN: AP9617 HR: A10 SN: JA0243028055 MD:10/25/2002) 
# (Embedded PowerNet SNMP Agent SW v2.2 compatible)
200:200:200:200:400:200:405:405:400:405:405:405:200:404:404:404:400:400:405:405:404:200:405:405:+++::Allegro-Software-RomPager/3.10
# CISCO IP Phone 7940 series
200:200:405:200:400:200:405:405:400:405:405:405:200:404:404:404:400:400:405:405:405:405:405:405:400::Allegro-Software-RomPager/3.12
#
200:200:405:200:400:200:405:405:400:405:405:405:200:404:404:404:400:400:400:405:405:405:405:405:400::Allegro-Software-RomPager/4.06
#
200:200:400:200:200:200:401:400:200:401:401:401:400:401:401:400:200:400:400:400:400:400:400:400:+++:^$:Ambit DOCSIS Cable Modem
200:200:200:200:400:200:400:501:200:400:400:400:200:200:404:400:400:501:404:404:200:501:501:501:400::AnWeb/1.40d
200:200:404:200:400:200:400:501:200:400:400:400:200:200:404:400:400:501:404:404:404:501:501:501:400:^AnWeb/1\.4[12][a-m]:AnWeb/1.41g-1.42m
200:200:---:200:200:200:---:200:200:200:---:---:200:200:200:---:200:---:---:---:---:---:---:---:+++::Apt-proxy 1.2.9.2
# OS: Debian unstable
# Kernel: Linux 2.6.4 with grsecurity 2.0
# Software: apt-proxy 1.3.6 (Port: tcp/9999 started over inetd)
200:200:---:200:200:200:---:200:200:200:---:---:200:200:---:---:200:---:---:---:---:---:---:---:+++::Apt-proxy 1.3.6
200:200:400:200:200:200:404:200:200:404:404:404:200:404:404:400:200:404:400:400:400:400:400:400:+++::ArGoSoft Mail Server Pro for WinNT/2000/XP, Version 1.8 (1.8.4.7)
# AXIS 540+/542+ Network Print Server V6.00 Jul  5 1999.
# AXIS 540+/542+ print servers with OS versions of V5.55 and V5.51
# have the same signature.
400:200:400:200:200:200:400:200:200:200:400:400:200:200:200:404:200:404:400:400:400:400:400:400:+++:^$:AXIS 540+/542+ Network Print Server
200:200:501:HTM:HTM:HTM:501:501:HTM:501:501:501:200:400:400:400:200:404:501:501:501:501:501:501:+++:^$:AXIS 205 version 4.03 Webcam
404:200:---:200:200:200:---:200:200:200:---:---:---:404:404:+++:200:404:---:---:---:---:---:---:+++::3ware/1.0
# Device: Efficient 5865 DMT-ISDN Router (5865-002) v5.3.90 Ready
xxx:200:400:505:400:400:400:200:400:200:400:400:200:400:400:400:200:404:404:404:404:404:404:404:+++::Agranat-EmWeb/R4_01
# Netscreen-5XT 10 user with OS NS5rc04
HTM:200:200:505:400:400:400:200:400:200:400:400:200:400:400:400:400:303:405:405:200:200:405:405:+++::Virata-EmWeb/R6_0_1
# Agranat-EmWeb/R5_2_6
# Virata-EmWeb/R6_2_1
HTM:200:200:505:400:400:400:200:400:200:400:400:200:400:400:+++:400:404:404:404:404:200:404:404:+++:^(Agranat|Virata)-EmWeb/R[56]_2_[16]:Agranat-EmWeb/R5_2_6 or Virata-EmWeb/R6_2_1
# More precise! 
# From 3com nbx 100 voip call manager. vxworks os, 3com nbx firmware v 4_2_7
HTM:200:200:505:400:400:400:200:400:200:400:400:200:400:400:400:400:404:404:404:404:200:404:404:+++::Virata-EmWeb/R6_0_3
# From Lucent Technologies Cajun P333 R
xxx:200:200:505:400:400:400:200:400:200:400:400:200:400:400:400:400:404:404:404:404:200:404:404:404::Agranat-EmWeb/R5_1_2
# Less precise than above - might be the same
xxx:200:200:505:400:400:400:200:400:200:400:400:200:400:400:400:400:404:404:404:404:200:404:404:+++::Virata-EmWeb/R6_0_1
HTM:200:200:505:400:400:400:200:400:200:400:400:200:400:400:400:400:405:405:405:200:200:405:405:+++:Virata-EmWeb/R5_3_0:Cisco VPN 3000 Concentrator Series Manager (Virata-EmWeb/R5_3_0)
HTM:200:200:505:400:400:400:200:400:200:400:400:200:400:400:400:400:200:405:405:200:200:405:405:+++:Virata-EmWeb/R5_3_0:Cisco VPN 3000 Concentrator Series Manager (Virata-EmWeb/R5_3_0)
HTM:200:200:505:400:400:400:200:400:200:400:400:---:400:400:+++:400:404:404:404:404:200:404:404:+++::Virata-EmWeb/R6_2_1
HTM:---:200:505:400:400:400:200:400:200:400:400:---:400:400:+++:400:404:404:404:404:200:404:404:+++::Virata-EmWeb/R6_2_1
# AOL application server
HTM:200:404:200:HTM:HTM:400:HTM:HTM:200:400:400:200:404:200:200:200:404:404:404:404:404:404:404:200:^AOLserver/3\.[3-5]\.:AOLserver/3.3.1 to 3.5.6
HTM:200:404:200:HTM:HTM:---:HTM:HTM:200:---:---:200:200:200:+++:+++:404:404:404:404:404:404:404:+++:AOLserver/4\.:AOLserver/4.0
## Is this real? ##
# Apache/1.0.0
# Apache/1.0.5
HTM:200:400:200:200:200:HTM:501:200:HTM:HTM:HTM:200:400:400:400:200:501:501:501:501:501:501:501:200:^Apache/1\.0\.[0-5]:Apache/1.0.0 to 1.0.5
HTM:200:400:200:200:200:HTM:501:200:HTM:HTM:HTM:200:400:400:400:200:501:501:501:501:501:501:501:403::Apache/1.0.3
HTM:200:400:200:200:200:HTM:200:200:HTM:HTM:HTM:200:400:400:400:400:501:501:501:501:501:501:501:200::Apache/1.1.1
HTM:200:400:200:200:200:HTM:501:200:HTM:HTM:HTM:200:400:400:400:400:501:501:501:501:501:501:501:403:^Apache/1\.1\.[1-3]:Apache/1.1.1 to 1.1.3
# Stronghold/1.3.4 Ben-SSL/1.3 Apache/1.1.3
HTM:200:400:200:200:200:HTM:501:200:HTM:HTM:HTM:200:400:400:400:400:501:501:501:501:501:501:501:200:^([A-Za-z_-]+/[0-9.]+ )?Apache/1\.1\.[1-3]$:Apache/1.1.1 to 1.1.3
HTM:200:400:200:200:200:HTM:501:200:HTM:HTM:HTM:200:400:400:400:400:501:501:501:501:501:501:501:302::Apache/1.1.3
# suspicious signature
---:200:200:200:200:200:---:200:200:200:---:---:200:400:400:400:400:404:405:405:200:200:405:501:200::Apache/2.0.55 (Unix)
#
HTM:403:403:403:403:403:HTM:403:403:403:HTM:HTM:403:400:400:400:400:403:403:403:403:403:403:403:403::Apache/2 with mod_dosevasive
HTM:200:200:200:200:200:HTM:501:200:200:HTM:HTM:200:400:400:400:400:404:405:405:200:200:405:405:403::Apache/2.0.39 (Unix) DAV/2
# Apache/2.0.48 (Unix) PHP/4.3.4 mod_python/3.1.2b Python/2.3.2
# Apache/2.0.48 (Unix) -- Apache2 or Apache21 on FreeBSD 5.2.1
##HTM:200:200:200:200:200:HTM:501:200:200:HTM:HTM:200:400:400:+++:400:404:405:405:200:200:405:501:200:^Apache(/2(\.0(\.4[678])?)?)?:Apache/2.0.46-48 (Unix)
# More precise
# Apache2 on Linux Gentoo (2.0.46, 2.0.47, 2.0.47-r1, 2.0.48-r1, 2.0.48, 2.0.49-r1) 
# Apache-AdvancedExtranetServer/2.0.50 (Mandrakelinux/5mdk) mod_ssl/2.0.50 OpenSSL/0.9.7d PHP/4.3.8
# Apache/2.0.53 (FreeBSD) PHP/4.3.10
# Apache/2.0.58 (Gentoo)
HTM:200:200:200:200:200:HTM:501:200:200:HTM:HTM:200:400:400:400:400:404:405:405:200:200:405:501:200:^Apache(-AdvancedExtranetServer)?(/2(\.0(\.(4[6-9]|5[0-8]).*)?)?)?$:Apache/2.0.46-58 (Unix)
# Apache 2.0.48 on Gentoo, with DAV enabled
# Apache/2.0.40 (Unix) DAV/2 PHP/4.3.3
# Apache/2.0.47 (Unix) mod_perl/1.99_12 Perl/v5.8.1 PHP/4.3.4 mod_ssl/2.0.47 OpenSSL/0.9.7b DAV/2 [on Darwin]
##HTM:200:200:200:200:200:HTM:501:200:200:HTM:HTM:200:400:400:+++:400:404:405:405:200:200:405:405:200:Apache(/2(\.0(\.4[0-8]( +\((Gentoo/Linux|Unix)\)(.* DAV/2.*)?)?)?)?)?$:Apache/2.0.4x with DAV/2 on Linux
# More precise
# Apache-AdvancedExtranetServer/2.0.48 (Mandrake Linux/6mdk) mod_ssl/2.0.48 OpenSSL/0.9.7c DAV/2 PHP/4.3.4
# Apache/2.0.40 (Red Hat Linux)
# IBM_HTTP_Server/2.0.42 2.0.42 (Unix) DAV/2
# IBM_HTTP_Server/2.0.42.2 Apache/2.0.46 (Unix) DAV/2
# Apache/2.0.48 (Unix) DAV/2
# Apache/2.0.48 (Fedora)
# Apache/2.0.50 (Trustix Secure Linux/Linux) mod_ssl/2.0.50 OpenSSL/0.9.7c DAV/2 PHP/5.0.0-dev
# Apache/2.0.46 (Red Hat)
# Apache/2.0.51 (Fedora)
# Apache-AdvancedExtranetServer/2.0.48 (Mandrake Linux/6.6.100mdk) mod_perl/1.99_11 Perl/v5.8.3 mod_ssl/2.0.48 OpenSSL/0.9.7c DAV/2 PHP/4.3.4
# Apache/2.0.52 (Unix) DAV/2 Resin/3.0.9
# Apache-AdvancedExtranetServer/2.0.53 (Mandrakelinux/PREFORK-9mdk) mod_auth_external/2.2.9 mod_ssl/2.0.53 OpenSSL/0.9.7d DAV/2 PHP/4.3.10 mod_perl/1.999.21 Perl/v5.8.6
# Apache/2.2.2 (iTools 8.2.2)/Mac OS X) mod_ssl/2.2.2OpenSSL/0.9.7i DAV/2 mod_fastcgi/2.4.2 PHP/5.1.5
# Apache/2.2.3 (Gentoo) DAV/2 mod_ssl/2.2.3 OpenSSL/0.9.8c
HTM:200:200:200:200:200:HTM:501:200:200:HTM:HTM:200:400:400:400:400:404:405:405:200:200:405:405:200:^(Apache(-AdvancedExtranetServer)?|IBM_HTTP_Server)/2\.(0\.(4[0-9]|5[0-3])|2\.[0-3]) \([a-zA-Z ]*(Unix|[lL]inux|Fedora|Red Hat|Gentoo|.*Mac OS X)[a-zA-Z0-9/-]*\):Apache/2.0.40-2.2.3 (Unix)
# Apache/2.0.48 (Unix) mod_ssl/2.0.48 OpenSSL/0.9.7d PHP/4.3.5 mod_python/3.1.2b Python/2.3.3
# Apache 2 on Debian GNU/Linux 3.0r2 with:
# core mod_access mod_auth mod_include mod_log_config mod_env mod_expires
# mod_unique_id mod_setenvif mod_ssl prefork http_core mod_mime mod_status
# mod_autoindex mod_asis mod_cgi mod_negotiation mod_dir mod_imap
# mod_actions mod_userdir mod_alias mod_rewrite mod_so sapi_apache2
# mod_python
# Apache/2.0.49 (FreeBSD) PHP/4.3.7 mod_ssl/2.0.49 OpenSSL/0.9.7c-p1
XML:200:200:200:200:200:XML:200:200:200:XML:XML:200:400:400:400:400:404:405:405:200:200:405:501:200:^Apache/2\.0\.4[89] \(Unix|FreeBSD\):Apache/2.0.48-49 (Unix)
#
# Same signature as above??
# Apache/2.0.40 (Red Hat Linux)
# Apache/2.0.47 (Unix) DAV/2 SVN/0.32.1+
# Apache/2.0.48 (Unix) DAV/2
##HTM:200:200:200:200:200:HTM:501:200:200:HTM:HTM:200:400:400:+++:400:404:405:405:200:200:405:405:+++::Apache/2.0.x w/ WebDAV?
# Apache/2.0.40 (Red Hat Linux) [httpd-2.0.40-21 on Redhat 9]
# Apache/2.0.47 (Fedora)
# Apache/2.0.48 (Fedora)
# Apache/2.0.51 (Unix) mod_ssl/2.0.51 OpenSSL/0.9.7d DAV/2 PHP/4.3.8
# Apache/2.0.54 (Debian GNU/Linux) DAV/2 PHP/4.3.10-15
# Apache/2.2.0 (FreeBSD) mod_ssl/2.2.0
HTM:200:200:200:200:200:HTM:200:200:200:HTM:HTM:200:400:400:400:400:404:405:405:200:200:405:405:200:^Apache/2\.(2\.[0-9]|0\.(4[0-9]|5[0-4])) \(Fedora|[A-Za-z/ ]*Linux|Unix\):Apache/2.0.40-2.2.0 (Unix)
HTM:200:200:200:200:200:HTM:501:200:200:HTM:HTM:200:400:400:400:400:404:405:405:200:400:405:501:200::Apache/2.0.54 (Debian GNU/Linux) mod_python/3.1.3 Python/2.3.5 PHP/4.3.10-16 mod_perl/1.999.21 Perl/v5.8.4
HTM:200:200:200:200:200:HTM:404:200:200:404:HTM:200:404:404:404:400:404:404:404:200:200:404:404:200::Apache/2.0.40 (Unix)
HTM:200:403:200:200:200:HTM:200:200:200:HTM:HTM:200:400:400:400:400:404:405:404:200:200:404:501:200::Apache/1.3.20 (Trustix Secure Linux/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6 PHP/4.1.0
HTM:200:200:200:200:200:HTM:501:200:200:HTM:HTM:200:400:400:400:400:403:403:403:403:200:403:403:200::Apache/1.3.20 (Unix) mod_ssl/2.8.4 OpenSSL/0.9.6b mod_jk/1.2.1 PHP/4.3.6 AuthMySQL/2.20 Resin/1.2.0
# Apache/1.3.29 Ben-SSL/1.53 (Debian GNU/Linux) PHP/4.3.4
# Apache/1.3.27 (Trustix Secure Linux/Linux) PHP/3.0.18
# Apache/1.3.33 (Unix) Resin/2.1.14 mod_ssl/2.8.22 OpenSSL/0.9.7d PHP/4.3.9
HTM:200:200:200:400:400:HTM:200:400:200:HTM:HTM:200:400:400:400:400:404:403:403:200:200:403:501:200:^Apache/1\.3\.(2[7-9]|3[0-3]):Apache/1.3.27-33 (Linux)
# Apache/1.3.31 (Unix)
# Apache/1.3.27 (Trustix Secure Linux/Linux) PHP/4.0.6
HTM:200:200:200:400:400:HTM:200:400:200:HTM:HTM:200:400:400:400:400:302:405:302:200:200:302:501:200:^Apache/1.3.(2[7-9|3[01]):Apache/1.3.27-31 (Unix)
XML:200:200:200:400:400:XML:501:400:200:HTM:XML:200:400:400:400:400:404:405:404:200:200:404:501:200::Apache/1.3.27 (Trustix Secure Linux/Linux)
HTM:200:200:200:400:400:HTM:501:400:200:HTM:HTM:200:400:400:400:400:404:403:403:200:200:404:501:302::Apache/1.3.27 (Unix)  (Red-Hat/Linux) mod_perl/1.26 PHP/4.3.3 FrontPage/5.0.2 mod_ssl/2.8.12 OpenSSL/0.9.6b
# Apache/1.3.22 (Unix)  (Red-Hat/Linux) mod_python/2.7.8 Python/1.5.2 mod_ssl/2.8.5 OpenSSL/0.9.6b DAV/1.0.2 PHP/4.0.6 mod_perl/1.26 mod_throttle/3.1.2
# Apache/1.3.22 (Unix)  (Red-Hat/Linux) Carrot-1.0.7 PHP/4.3.0 mod_perl/1.21
#HTM:200:200:200:400:400:HTM:400:400:200:HTM:HTM:200:400:400:+++:400:404:403:403:200:200:404:501:+++::Apache/1.3.22 (Unix)  (Red-Hat/Linux)
# Apache/1.3.26 (Unix) PHP/4.2.3 mod_perl/1.26
# Apache/1.3.26 (Unix) PHP/4.1.2
# Apache/1.3.22 (Unix)  (Red-Hat/Linux) mod_ssl/2.8.7 OpenSSL/0.9.6b PHP/4.1.2 mod_throttle/3.1.2
HTM:200:200:200:400:400:HTM:400:400:200:HTM:HTM:200:400:400:400:400:404:403:403:200:200:404:501:200:^Apache/1\.3\.2[2-6] \(Unix\) .*PHP/4\.:Apache/1.3.22-26 (Unix) PHP/4
HTM:200:200:200:400:400:HTM:400:400:200:HTM:HTM:200:400:400:+++:400:404:200:200:200:200:404:501:+++::Apache/1.3.22 (Unix)  (Red-Hat/Linux) mod_perl/1.23
# Apache/2.0.48 (Unix) PHP/4.3.4
# Apache/2.0.45 (Unix) mod_ssl/2.0.45 OpenSSL/0.9.7a PHP/4.3.3
# Apache-AdvancedExtranetServer/2.0.47 (Mandrake Linux/6mdk) mod_perl/1.99_09 Perl/v5.8.1 mod_ssl/2.0.47 OpenSSL/0.9.7b PHP/4.3.2
# Apache/2.0.48 (Unix) PHP/4.3.4
# Apache/2.0.50 (Trustix Secure Linux/Linux) mod_jk2/2.0.2 PHP/4.3.8 mod_ssl/2.0.50 OpenSSL/0.9.7c
# Apache/2.0.50 (FreeBSD)
# Apache/2.0.53 (FreeBSD) PHP/4.3.10
HTM:200:200:200:200:200:HTM:200:200:200:HTM:HTM:200:400:400:400:400:404:405:405:200:200:405:501:200:^Apache(-AdvancedExtranetServer)?(/2\.0\.(4[5-9]|5[0-3]) .*)?$:Apache/2.0.45-53 PHP/4.3.3-10
HTM:200:200:200:200:200:HTM:200:200:200:HTM:HTM:200:400:400:400:400:302:405:405:200:200:405:501:200::Apache/2.0.54 (FreeBSD) PHP/4.3.11
# Apache/2.0.48 (Fedora)
# Apache/2.0.49 (Debian GNU/Linux) mod_perl/1.99_12 Perl/v5.8.3 PHP/4.3.5 mod_ssl/2.0.49 OpenSSL/0.9.7d
HTM:200:200:200:200:200:HTM:200:200:200:HTM:HTM:200:400:400:400:400:200:200:200:200:200:200:200:200:^Apache/2\.0\.4[89]:Apache/2.0.48-49 (Linux)
# Apache/2.0.49 (Trustix Secure Linux/Linux) [Trustix 2.1]
# Apache/2.0.48 (Trustix Secure Linux/Linux) PHP/4.3.4
XML:200:200:200:200:200:XML:501:200:200:HTM:XML:200:400:400:400:400:404:405:405:200:200:405:501:200:^Apache(/2.0.4[89].*)?$:Apache/2.0.48-49 (Trustix Secure Linux)
# Apache/2.0.48 (Fedora) - X-Powered-By: PHP/4.3.4
HTM:200:200:200:200:200:HTM:200:200:200:HTM:HTM:200:302:302:302:400:302:302:302:200:200:302:302:200::Apache/2.0.48 (Fedora) [w/ PHP/4.3.4]
HTM:200:200:200:200:200:HTM:200:200:200:HTM:HTM:200:400:400:400:400:VER:405:405:200:200:405:501:200::Apache/2.0.51 (Trustix Secure Linux/Linux) mod_ssl/2.0.51 OpenSSL/0.9.7c PHP/4.3.9
#
# Apache/1.3.24 (Unix) PHP/4.2.1
# Apache/1.3.23 (Unix)  (Red-Hat/Linux) PHP/4.2.2
# Apache/1.3.23 (Unix) PHP/4.1.2
# Apache/1.3.12 (Unix) PHP/4.1.2
##HTM:200:200:200:200:200:HTM:200:200:200:HTM:HTM:200:400:400:+++:400:404:405:404:200:200:404:501:+++:^Apache/1\.3\[12][234] .*Unix.*PHP/4\.[12]\.[12]:Apache/1.3.12-24 w/ PHP/4.x
# Apache/1.3.23 (Unix) PHP/4.1.2
# Apache/1.3.12 (Unix) ApacheJServ/1.1 mod_ssl/2.6.4 OpenSSL/0.9.5a mod_perl/1.22
HTM:200:200:200:200:200:HTM:200:200:200:HTM:HTM:200:400:400:400:400:404:405:404:200:200:404:501:403:^Apache/1\.3\.(1[2-9]|2[0-3]) \(Unix\):Apache/1.3.12-23 (Unix)
#
HTM:403:200:200:403:403:HTM:501:403:403:HTM:HTM:403:400:400:400:400:404:405:404:200:200:404:501:403::Apache/1.3.14 (Unix) Resin/2.1.4 PHP/4.0.4pl1
HTM:200:200:200:200:200:HTM:200:200:200:HTM:HTM:200:400:400:400:400:404:405:404:200:200:404:501:400::Apache/1.3.20 (Unix) Resin/2.1.1 mod_ssl/2.8.4 OpenSSL/0.9.4
# Apache/1.3.20 Sun Cobalt (Unix) mod_ssl/2.8.4 OpenSSL/0.9.6b PHP/4.0.6 mod_auth_pam_external/0.1 FrontPage/4.0.4.3 mod_perl/1.25
# Apache/1.3.20 Sun Cobalt (Unix) Chili!Soft-ASP/3.6.2 mod_ssl/2.8.4 OpenSSL/0.9.6b PHP/4.0.6 mod_auth_pam_external/0.1 FrontPage/4.0.4.3 mod_perl/1.25
# Apache/1.3.14 (Unix) PHP/4.3.4 rus/PL30.0
# Apache/1.3.24 (Unix) PHP/4.2.3 rus/PL30.12
# Apache/1.3.20 Sun Cobalt (Unix)
# Apache/1.3.20 (Linux/SuSE) mod_perl/1.26 mod_ssl/2.8.4 OpenSSL/0.9.6b
# Apache/1.3.12 (Unix) Resin/1.2.0
# Oracle9iAS/9.0.2.3.0 Oracle HTTP Server
HTM:200:200:200:200:200:HTM:200:200:200:HTM:HTM:200:400:400:400:400:404:405:404:200:200:404:501:200:^(Oracle9iAS/9.0.2.3.0 Oracle HTTP Server|Apache/1\.3\.(1[2-9]|2[04]) .*\(Unix|Linux[/A-Za-z]*\)):Apache/1.3.12-24 (Unix) [might be Oracle HTTP Server]
# Apache/1.3.27 (Unix)  (Red-Hat/Linux) mod_ssl/2.8.12 OpenSSL/0.9.6b PHP/4.1.2 mod_throttle/3.1.2
# Apache/1.3.31 (Unix) PHP/4.3.8
# Apache/1.3.31
HTM:200:200:200:400:400:HTM:501:400:200:HTM:HTM:200:400:400:400:400:200:405:200:200:200:200:501:200:^Apache/1\.3\.(2[7-9|3[01]) \(Unix\):Apache/1.3.27-31 (Unix)
HTM:200:200:200:400:400:HTM:500:400:200:HTM:HTM:200:400:400:400:400:404:405:404:200:200:404:501:403::Apache/1.3.31 (Unix) mod_jk/1.2.1 mod_ssl/2.8.19 OpenSSL/0.9.7d
##HTM:200:200:200:400:400:HTM:501:400:200:HTM:HTM:200:400:400:+++:400:404:403:403:200:200:404:501:+++::Apache/1.3.27 (Unix)  (Red-Hat/Linux) mod_python/2.7.8 Python/1.5.2 mod_ssl/2.8.12 OpenSSL/0.9.6b DAV/1.0.3 PHP/4.1.2 mod_perl/1.26 mod_throttle/3.1.2
HTM:200:200:200:200:200:HTM:501:200:200:HTM:HTM:200:400:400:400:400:200:405:200:200:200:200:501:200::Apache/1.3.23 (Unix) DAV/1.0.3 PHP/4.3.3
HTM:200:200:200:200:200:HTM:501:200:200:HTM:HTM:200:---:400:400:400:404:405:404:200:200:404:501:200::Apache/1.3.23 (Unix)  (Red-Hat/Linux) Resin/2.1.3 mod_ssl/2.8.7 OpenSSL/0.9.6b DAV/1.0.3 PHP/4.1.2 mod_perl/1.26
HTM:200:200:200:400:400:HTM:400:400:200:HTM:HTM:200:400:400:400:400:403:403:403:200:403:404:501:403::Apache/1.3.26 (Unix) FrontPage/5.0.2.2623
# Apache/1.3.26 (Unix) mod_ssl/2.8.9 OpenSSL/0.9.6b rus/PL30.14
# Apache/1.3.26 (Unix) Resin/2.0.2 PHP/4.3.2
---:200:200:200:400:400:---:400:400:200:HTM:---:200:400:400:400:400:404:405:404:200:200:404:501:200::Apache/1.3.26 (Unix)
HTM:200:200:200:400:400:HTM:400:400:200:HTM:HTM:200:400:400:400:400:404:405:404:200:403:404:501:403::Apache/1.3.26 (Unix) FrontPage/5.0.2.2623
HTM:200:200:200:400:400:HTM:501:400:200:HTM:HTM:200:400:301:301:400:404:403:403:200:403:501:501:200::Apache/1.3.28 (Unix) mod_accel/1.0.30 mod_deflate/1.0.19 mod_ssl/2.8.15 OpenSSL/0.9.7a
HTM:200:200:200:400:400:HTM:403:400:200:HTM:HTM:200:400:301:301:400:404:405:403:403:200:403:403:403::Apache/1.3.28 (Unix) mod_accel/1.0.30
HTM:406:200:200:400:400:HTM:406:400:406:HTM:HTM:406:400:400:400:400:406:405:404:200:200:404:501:406::Apache/1.3.31 (Unix) PHP/4.3.7
# Apache/1.3.31 (Unix) mod_jk/1.2.5 FrontPage/5.0.2.2635 mod_fastcgi/2.4.2 mod_throttle/3.1.2 PHP/4.3.8 mod_ssl/2.8.18 OpenSSL/0.9.7d
# Apache/1.3.27 OpenSSL/0.9.6 (Unix) FrontPage/5.0.2.2510
# Apache/1.3.31 (Unix) FrontPage/5.0.2.2510
HTM:200:200:200:400:400:HTM:501:400:200:HTM:HTM:200:400:400:400:400:404:403:403:200:200:404:501:403:^Apache/1\.3\.(2[7-9]|3[01]) .*\(Unix\):Apache/1.3.27-31 (Unix)
HTM:200:200:200:400:400:HTM:200:400:200:HTM:HTM:200:400:400:400:400:404:403:403:200:200:404:501:403::Apache/1.3.27 (Unix)
HTM:200:200:200:400:400:HTM:501:400:200:HTM:HTM:200:302:302:302:400:404:405:404:200:200:404:501:+++::Apache/1.3.27 (Unix) mod_jk/1.2.2 mod_ssl/2.8.14 OpenSSL/0.9.7a
HTM:200:403:200:400:400:HTM:200:400:200:HTM:HTM:200:400:400:400:400:200:405:404:200:200:404:501:200::Apache/1.3.27 (Unix) PHP/4.2.3
# Apache/1.3.31 (Unix) mod_ssl/2.8.19 OpenSSL/0.9.7d PHP/4.3.8
# Apache/1.3.31 (Debian GNU/Linux) mod_jk/1.2.2-dev
# Apache/1.3.28 (Unix) PHP/4.3.7
# Apache/1.3.27
HTM:200:200:200:400:400:HTM:403:400:200:HTM:HTM:200:400:400:400:400:404:403:403:200:200:403:403:200:^Apache/1\.3\.(2[789]|3[01])( \(Unix|[A-Za-z/ ]*Linux\).*)?$:Apache/1.3.27-31 (Unix)
xxx:200:200:200:400:400:xxx:200:400:200:xxx:xxx:200:400:400:400:400:404:403:403:200:200:404:501:200::Apache/1.3.31 (Unix) Resin/2.1.10 mod_throttle/3.1.2 mod_ssl/2.8.19 OpenSSL/0.9.7d
HTM:200:404:200:400:400:HTM:501:400:200:HTM:HTM:200:400:400:400:400:404:404:404:404:200:404:404:200::Apache/1.3.29 (Debian GNU/Linux) PHP/4.3.3 mod_ssl/2.8.9 OpenSSL/0.9.6g
# Apache/1.3.29 (Debian GNU/Linux) mod_gzip/1.3.26.1a mod_perl/1.29 PHP/4.3.4
# Apache/1.3.27 (Unix) (Red-Hat/Linux) mod_ssl/2.8.12 OpenSSL/0.9.6b DAV/1.0.2 PHP/4.1.2 mod_perl/1.26
# Apache/1.3.33 (ALT Linux/alt1) PHP/4.3.10-ALT
HTM:200:200:200:400:400:HTM:200:400:200:HTM:HTM:200:400:400:400:400:200:200:200:200:200:200:200:200:^Apache/1\.3\.(2[7-9]|3[0-3]):Apache/1.3.27-33 (Unix)
# Apache/2.0.40 (Red Hat Linux)
# Apache/2.0.46 (Red Hat)
# Apache/2.0.48 (Fedora)
# Apache/2.0.49 (Fedora)
# Apache/2.0.50 (Fedora)
HTM:200:200:200:200:200:HTM:501:200:200:XML:HTM:200:400:400:400:400:404:405:405:200:200:405:405:200:^Apache/2\.0\.(4[0-9]|50) \(Fedora|Red Hat( Linux)?\):Apache/2.0.40-50 (Red Hat Linux)
##HTM:200:200:200:400:400:HTM:400:400:200:HTM:HTM:200:400:400:+++:+++:404:405:404:200:200:404:501:+++:^Apache(/1.3.2[36].*)?$:Apache/1.3.26 (FreeBSD) or Apache/1.3.23 (Red-Hat/Linux)
# New sig
# Apache-AdvancedExtranetServer
# Apache-AdvancedExtranetServer/1.3.23 (Mandrake Linux/4.2mdk) mod_ssl/2.8.7 OpenSSL/0.9.6c PHP/4.1.2
# Apache-AdvancedExtranetServer/1.3.23 (Mandrake Linux/4.2mdk) PHP/4.1.2 mod_ssl/2.8.7 OpenSSL/0.9.6c
# Apache-AdvancedExtranetServer/1.3.26 (Mandrake Linux/6.1mdk) mod_ssl/2.8.10 OpenSSL/0.9.6g PHP/4.2.3
# Apache-AdvancedExtranetServer/1.3.26 (Mandrake Linux/6.3.90mdk) FrontPage/5.0.2.2623 PHP/4.2.3
# Apache-AdvancedExtranetServer/1.3.26 (Mandrake Linux/6mdk) sxnet/1.2.4 mod_ssl/2.8.10 OpenSSL/0.9.6g PHP/4.2.3
# Apache-AdvancedExtranetServer/1.3.26 (Mandrake Linux/6mdk) sxnet/1.2.4 mod_ssl/2.8.10 OpenSSL/0.9.6g PHP/4.3.4
# Apache/1.3.26 (Unix) Debian GNU/Linux PHP/4.1.2
# Apache/1.3.22 (Unix)  (Red-Hat/Linux) DAV/1.0.2 PHP/4.1.2 mod_perl/1.26
HTM:200:200:200:400:400:HTM:400:400:200:HTM:HTM:200:400:400:400:400:404:405:404:200:200:404:501:200:^Apache(-AdvancedExtranetServer)?(/1\.3\.2[2-6].*)?$:Apache/1.3.22-26 (Unix)
HTM:200:200:200:400:400:HTM:400:400:200:HTM:HTM:200:400:400:+++:400:404:404:404:200:200:404:404:+++::Apache/1.3.26 (Unix) mod_perl/1.27 PHP/4.2.2
HTM:200:403:200:400:400:HTM:400:400:200:HTM:HTM:200:400:400:+++:400:403:403:403:403:200:403:403:+++::Apache/1.3.26 (Unix) mod_fastcgi/2.2.12
HTM:200:200:200:400:400:HTM:400:400:200:HTM:HTM:200:400:400:400:400:404:405:404:200:403:404:501:200:^Apache(/1\.3\.26.*)?$:Apache/1.3.26 (Debian 3.0 woody)
xxx:200:200:200:400:400:xxx:200:400:200:xxx:xxx:200:400:400:400:400:404:405:405:200:200:501:501:200::IBM_HTTP_SERVER/1.3.26  Apache/1.3.26 (Unix)
# Apache/1.3.26 (Darwin) PHP/4.1.2 mod_perl/1.26
# Apache/1.3.26 (Unix)
# Apache/1.3.26 Ben-SSL/1.48 (Unix) PHP/4.2.3
HTM:200:200:200:400:400:HTM:400:400:200:HTM:HTM:200:400:400:400:400:404:405:404:200:200:404:501:403:^Apache/1\.3\.26 .*\((Unix|Darwin|[A-Za-z ]*Linux)\):Apache/1.3.26 (Unix)
# Apache/1.3.22 (Unix)  (Red-Hat/Linux) mod_ssl/2.8.5 OpenSSL/0.9.6b DAV/1.0.2 PHP/4.3.0 mod_perl/1.26
# Apache/1.3.26 (Unix) mod_throttle/3.1.2 PHP/4.0.6
HTM:200:200:200:400:400:HTM:400:400:200:HTM:HTM:200:400:400:400:400:404:403:403:200:200:403:403:200:^Apache/1\.3\.2[2-6] \(Unix\):Apache/1.3.22-26 (Unix)
HTM:200:200:200:400:400:HTM:400:400:200:HTM:HTM:200:400:400:400:400:404:403:403:200:403:404:501:403::Apache/1.3.26 (Unix) FrontPage/5.0.2.2623
HTM:200:403:200:400:400:HTM:400:400:200:HTM:HTM:200:200:200:200:400:200:403:403:403:200:403:403:200::Apache/1.3.26 (Unix) Debian GNU/Linux mod_ssl/2.8.9 OpenSSL/0.9.6c mod_perl/1.26
HTM:200:200:200:400:400:HTM:400:400:200:HTM:HTM:200:400:400:400:400:302:401:401:200:200:401:401:200::Apache/1.3.26 (Unix) Debian GNU/Linux PHP/4.3.4 AuthMySQL/3.1 DAV/1.0.3
#
---:200:200:200:200:200:---:501:200:200:HTM:---:200:400:400:400:400:404:403:403:200:200:404:501:200::Apache/1.3.12 (Unix)  (SuSE/Linux) mod_fastcgi/2.2.2 mod_perl/1.24 PHP/4.2.2 mod_ssl/2.6.5 OpenSSL/0.9.5a
# Apache1 on Linux Gentoo 1.4 (1.3.27-r3, 1.3.27-r4, 1.3.18, 1.3.28-r1, 1.3.29)
##HTM:200:403:200:400:400:HTM:501:400:200:HTM:HTM:200:400:400:+++:400:404:405:404:200:200:404:501:200:^Apache(/1\.3\.2[789]( +\(Unix\) +\(Gentoo/Linux\))?)?$:Apache/1.3.2x on Gentoo/Linux
# Apache/1.3.29
# Apache/1.3.28 (Unix) PHP/4.3.3 on FreeBSD 4.9 x86, default install
# IBM_HTTP_SERVER/1.3.26.2  Apache/1.3.26 (Unix)
# IBM_HTTP_SERVER/1.3.26  Apache/1.3.26 (Unix)
# Apache/1.3.27 (NETWARE)
# Apache/1.3.31 (Unix) PHP/4.3.6 mod_ssl/2.8.17 OpenSSL/0.9.7d rus/PL30.20
# Apache/1.3.27 OpenSSL/0.9.6 (Unix)
# Apache/1.3.29 (Unix) mod_ssl/2.8.16 OpenSSL/0.9.7c PHP/4.3.4
# Apache/1.3.27 (Unix) PHP/4.1.2 ApacheJServ/1.1.2
# Apache/1.3.33 (Unix)
HTM:200:200:200:400:400:HTM:501:400:200:HTM:HTM:200:400:400:400:400:404:405:404:200:200:404:501:403:^Apache(/1\.3\.(2[789]|3[0-3]).*)?$:Apache/1.3.27-33 (Unix/Netware)
HTM:200:200:200:400:400:---:400:400:---:---:---:200:400:400:400:400:404:405:404:200:200:400:400:403::IBM_HTTP_SERVER/1.3.26.2 Apache/1.3.26 (Unix) 
# Apache/1.3.28 (Unix) PHP/4.3.3
# Apache/1.3.31 (Trustix Secure Linux/Linux)
HTM:200:200:200:400:400:HTM:200:400:200:HTM:HTM:200:400:400:400:400:200:405:200:200:200:200:501:200:^Apache(/1\.3\.(2[89]|3[01]).*)?$:Apache/1.3.28-31 (Unix)
# Apache/1.3.31 (Unix) PHP/4.3.7 mod_ssl/2.8.18 OpenSSL/0.9.7d
# Apache/1.3.29 Ben-SSL/1.52 (Debian GNU/Linux) mod_perl/1.29
HTM:200:200:200:400:400:HTM:200:400:200:HTM:HTM:200:400:400:400:400:404:405:404:200:403:404:501:200:^Apache/1\.3\.(29\|3[01]) \(.*Unix.*\):Apache/1.3.29-31 (Unix)
# Apache/1.3.29 (Unix) mod_auth_passthrough/1.8 mod_log_bytes/1.2 mod_bwlimited/1.4 FrontPage/5.0.2.2634 mod_ssl/2.8.16 OpenSSL/0.9.7a PHP-CGI/0.1b
# Apache/1.3.27 (Unix)  (Red-Hat/Linux) mod_python/2.7.8 Python/1.5.2 mod_ssl/2.8.12 OpenSSL/0.9.6b DAV/1.0.3 PHP/4.1.2 mod_perl/1.26 mod_throttle/3.1.2
# Apache/1.3.31 (Unix) mod_auth_passthrough/1.8 mod_log_bytes/1.2 mod_bwlimited/1.4 PHP/4.3.8 FrontPage/5.0.2.2634a mod_ssl/2.8.19 OpenSSL/0.9.7a
# Apache/1.3.33 (Unix) Resin/3.0.9 mod_auth_passthrough/1.8 mod_log_bytes/1.2 mod_bwlimited/1.4 PHP/4.3.9 FrontPage/5.0.2.2635 mod_ssl/2.8.22 OpenSSL/0.9.7a
HTM:200:200:200:400:400:HTM:501:400:200:HTM:HTM:200:400:400:400:400:404:403:403:200:200:404:501:200:^Apache/1\.3\.(2[7-9]|3[0-3]) \(Unix\):Apache/1.3.27-33 (Unix)
# Apache/1.3.29 Ben-SSL/1.53
# Apache/1.3.27 OpenSSL/0.9.6 (Unix)
HTM:200:200:200:400:400:HTM:501:400:200:HTM:HTM:200:400:400:400:400:302:405:302:200:200:302:501:403:^Apache/1\.3\.2[7-9]:Apache/1.3.27-29
HTM:200:403:200:400:400:HTM:501:400:200:HTM:HTM:200:400:400:400:400:302:405:302:200:200:302:501:403::Apache/1.3.31 (Unix) mod_deflate/1.0.21 mod_accel/1.0.31 mod_ssl/2.8.19 OpenSSL/0.9.7d
HTM:200:200:200:400:400:HTM:501:400:200:HTM:HTM:200:302:302:302:400:302:405:302:200:200:302:501:200::Apache/1.3.27 (Unix)  (Red-Hat/Linux) FrontPage/5.0.2.2623 mod_ssl/2.8.12 OpenSSL/0.9.6b DAV/1.0.3 PHP/4.3.3 mod_perl/1.26
HTM:200:200:200:400:400:HTM:501:400:200:HTM:HTM:200:400:400:400:400:405:405:405:200:200:405:501:200::Apache/1.3.27 (Unix)
HTM:403:200:200:400:400:HTM:501:400:403:HTM:HTM:403:200:301:301:400:200:405:200:200:200:200:501:403::Apache/1.3.27 (Unix)
# Apache/1.3.28 (Unix) PHP/4.3.3
# Apache/1.3.27 (Unix) mod_throttle/3.1.2 PHP/4.3.2 FrontPage/5.0.2.2623 mod_ssl/2.8.14 OpenSSL/0.9.6b
# Apache/1.3.29 (Unix) PHP/4.3.8 mod_ssl/2.8.16 OpenSSL/0.9.6m
# Apache/1.3.31 (Unix) mod_auth_passthrough/1.8 mod_log_bytes/1.2 mod_bwlimited/1.4 PHP/4.3.8 FrontPage/5.0.2.2634a mod_ssl/2.8.19 OpenSSL/0.9.6b
HTM:200:200:200:400:400:HTM:501:400:200:HTM:HTM:200:400:400:400:400:302:405:302:200:200:302:501:200:^Apache/1\.3\.(2[79]|3[01]) \(Unix\):Apache/1.3.27-31 (Unix)
# Server's Module Magic Number: 19990320:15
# Compiled-in modules: http_core.c mod_charset.c mod_bandwidth.c mod_env.c mod_log_config.c mod_mime.c mod_negotiation.c mod_status.c 
# mod_include.c mod_autoindex.c mod_dir.c mod_cgi.c mod_asis.c mod_imap.c mod_actions.c mod_userdir.c mod_alias.c mod_rewrite.c
# mod_access.c mod_auth.c mod_proxy.c mod_expires.c mod_headers.c mod_so.c mod_setenvif.c mod_ssl.c 
HTM:200:200:200:400:400:---:200:400:200:HTM:HTM:200:400:400:400:400:302:405:302:200:200:302:501:403::Apache/1.3.29 (Unix) FrontPage/5.0.2.2623 mod_ssl/2.8.16 OpenSSL/0.9.7c rus/PL30.18
# Apache/1.3.29 (Unix) mod_ssl/2.8.16 OpenSSL/0.9.7d mod_fastcgi/2.4.2 Resin/2.1.12 PHP/4.3.8
# Apache/1.3.29 (Unix) mod_ssl/2.8.16 OpenSSL/0.9.7c mod_fastcgi/2.4.2 Resin/2.1.12 PHP/4.3.5RC2
400:200:400:200:400:400:400:400:400:200:400:400:200:400:400:400:200:411:411:403:403:403:403:403:200::Apache/1.3.29 (Unix)
HTM:302:403:200:400:400:HTM:302:400:302:HTM:HTM:302:302:302:302:400:200:405:200:200:200:200:501:302::Apache/1.3.29 (Unix) FrontPage/5.0.2.2623
HTM:301:403:200:400:400:HTM:403:400:301:HTM:HTM:301:400:400:400:400:200:403:403:200:200:403:403:301::Apache/1.3.29 (Unix) mod_jk/1.2.5
# Apache/1.3.28 Ben-SSL/1.52 (Unix) PHP/4.3.4
# Apache/1.3.29
# Apache/1.3.31 (Unix) PHP/4.3.8 mod_ssl/2.8.18 OpenSSL/0.9.7c-p1
# Apache/1.3.27 OpenSSL/0.9.6 (Unix) FrontPage/5.0.2.2510
# Apache/1.3.32 (Unix) PHP/4.3.9 mod_ssl/2.8.21 OpenSSL/0.9.7d
# Apache/1.3.33 (Unix) PHP/5.0.3
HTM:200:200:200:400:400:HTM:200:400:200:HTM:HTM:200:400:400:400:400:404:405:404:200:200:404:501:403:^Apache(/1\.3\.(2[7-9]|3[0-3]).*)?$:Apache/1.3.27-33 (Unix)
# Same signature??
# Apache/1.3.27 (Unix)  (Red-Hat/Linux) tomcat/1.0 mod_ssl/2.8.12 OpenSSL/0.9.6b DAV/1.0.3 PHP/4.1.2 mod_perl/1.26
# Apache/1.3.27 (Unix)  (Red-Hat/Linux) mod_ssl/2.8.12 OpenSSL/0.9.6b DAV/1.0.3 PHP/4.1.2 mod_perl/1.26
# Apache/1.3.27 (Unix) PHP/4.2.2 mod_perl/1.27 mod_ssl/2.8.12 OpenSSL/0.9.6g
# Apache/1.3.28 (Unix) mod_ssl/2.8.15 OpenSSL/0.9.7b
##HTM:200:200:200:400:400:HTM:501:400:200:HTM:HTM:200:400:400:+++:400:404:405:404:200:200:404:501:+++:^Apache/1\.3\.2[7-9] \(Unix\):Apache/1.3.27-28 on Redhat Linux
# Apache/1.3.26 + PHP under Debian 3.0
HTM:200:200:200:400:400:HTM:400:400:200:HTM:HTM:200:400:400:400:400:200:403:403:200:200:403:200:200::Apache/1.3.26 (Unix) Debian GNU/Linux PHP/4.1.2
HTM:200:403:200:400:400:HTM:400:400:200:HTM:HTM:200:400:400:400:400:404:405:404:200:200:404:501:403::Apache/1.3.26 (Unix)
HTM:200:200:200:400:400:HTM:400:400:200:HTM:HTM:200:400:200:200:400:200:200:200:200:200:200:200:200::Apache/1.3.26 (Linux/SuSE) mod_ssl/2.8.10 OpenSSL/0.9.6g mod_perl/1.27 mod_gzip/1.3.19.1a
# Apache/1.2.6 Red Hat
# Apache/1.2.4
# Apache/1.3.0 (Unix)
# Apache/1.3.3 (Unix)
##HTM:200:200:200:200:200:HTM:501:200:200:HTM:HTM:200:400:400:+++:400:404:405:404:200:200:501:501:+++:^Apache(/1\.(2\.[46]|3\.[03]).*)?$:Apache/1.2.4 to 1.3.3
# Two newer signatures more precise
# IBM_HTTP_Server/1.3.3.2 Apache/1.3.4-dev (Unix)
# IBM_HTTP_Server/1.3.3.3 Apache/1.3.4-dev (Unix)
# Stronghold/2.2 Apache/1.2.5 C2NetEU/2048-custom
HTM:200:200:200:200:200:HTM:501:200:200:HTM:HTM:200:400:400:400:400:404:405:404:200:200:501:501:403:^Apache(/1\.(2\.[0-6]|3\.0|3\.4-dev).*)?$:Apache/1.2.0 to 1.3.4-dev
# Apache/1.3.3 Cobalt (Unix)  (Red Hat/Linux)
# Apache/1.2b10
# Stronghold/2.1 Apache/1.2.4 UKWeb/2046
HTM:200:200:200:200:200:HTM:501:200:200:HTM:HTM:200:400:400:400:400:404:405:404:200:200:501:501:200:^Apache(/1\.(2\.([0-6]|[ab][0-9]+)|3\.[0-3]).*)?$:Apache/1.2.0 to 1.3.3
#
HTM:200:200:200:200:200:---:501:200:200:HTM:---:200:400:400:400:400:404:405:404:200:200:501:501:403::Apache/1.2.0
HTM:200:200:200:200:200:HTM:501:200:200:HTM:HTM:200:400:400:400:400:302:405:302:200:200:501:501:200::Apache/1.2.1
HTM:200:200:200:200:200:HTM:501:200:200:HTM:HTM:200:400:400:400:400:200:405:200:200:200:501:501:200::Apache/1.2.4
HTM:200:200:200:200:200:HTM:501:200:200:HTM:HTM:200:400:400:400:400:302:403:403:200:200:501:501:403::Apache/1.2.6 FrontPage/3.0.4.1
HTM:200:200:200:200:200:HTM:200:200:200:HTM:HTM:200:400:400:400:400:404:405:404:200:200:501:501:403::Apache/1.2.6 secured_by_Raven/1.2
400:200:200:200:200:200:400:200:200:200:400:400:200:400:400:400:200:404:405:400:200:200:400:400:403::Apache/1.2.6.46 WebTen/3.0 SSL/0.9.0b
HTM:200:200:200:200:200:HTM:501:200:200:HTM:HTM:200:400:400:400:400:404:403:403:200:200:501:501:403:^Apache/1\.2\.[4-6]:Apache/1.2.4 to 1.2.6
xxx:200:200:200:200:200:HTM:501:200:200:HTM:HTM:200:400:400:400:400:404:405:404:200:200:501:501:200::Apache/1.2.4
HTM:200:200:200:200:200:HTM:501:200:200:HTM:HTM:200:400:400:400:400:403:403:403:200:200:501:501:403::Apache/1.2.4
HTM:403:200:200:403:403:HTM:403:403:403:HTM:HTM:403:400:400:400:400:404:405:404:200:200:501:501:403::Apache/1.2.4 FrontPage/3.0.3
HTM:200:200:200:200:200:HTM:501:200:200:HTM:HTM:200:400:400:400:400:404:403:404:200:200:501:501:200::Apache/1.2.4 mod_perl/1.02
# Apache/1.3.3 Cobalt (Unix)  (Red Hat/Linux)
# Apache/1.2.4 PHP/FI-2.0
# Stronghold/2.2 Apache/1.2.5 C2NetUS/2002/php3.0.3
HTM:200:200:200:200:200:HTM:501:200:200:HTM:HTM:200:400:400:400:400:404:403:403:200:200:501:501:200:^([A-Za-z/0-9_.-]+ +)?Apache(/1\.(2\.[4-6]|3\.[0-3]).*)?$:Apache/1.2.4 to 1.3.3 (Unix)
HTM:200:403:200:200:200:HTM:501:200:200:HTM:HTM:200:400:400:400:400:404:405:404:200:200:501:501:403::Apache/1.2.4 rus/PL20.5
---:200:200:200:200:200:HTM:501:200:200:HTM:HTM:200:400:400:400:400:404:403:403:200:200:501:501:200::Apache/1.2.4 PHP/FI-2.0
# Apache/1.2.5
# Apache/1.2.6 Red Hat
HTM:200:200:200:200:200:HTM:200:200:200:HTM:HTM:200:400:400:400:400:404:405:404:200:200:501:501:200:^Apache(/1\.2\.[56] .*)?$:Apache/1.2.5-6 (Unix)
HTM:200:200:200:200:200:HTM:501:200:200:HTM:HTM:200:400:400:400:400:404:302:302:200:200:501:501:302::Apache/1.2.5 FrontPage/3.0.4
HTM:200:200:200:200:200:HTM:501:200:200:HTM:HTM:200:400:400:400:400:302:405:302:200:200:501:501:403:^Apache/1\.2\.[56]:Apache/1.2.5 or 1.2.6
xxx:200:403:200:200:200:HTM:501:200:200:HTM:HTM:200:400:400:400:400:404:405:404:200:200:501:501:403::Apache/1.2.6
HTM:200:200:200:200:200:HTM:302:200:200:HTM:HTM:200:302:302:302:302:302:302:302:200:200:302:302:302::Apache/1.2.6 FrontPage/3.0.4.1
HTM:200:403:200:200:200:HTM:501:200:200:HTM:HTM:200:400:400:400:400:302:405:302:200:200:501:501:200::Apache/1.2.6 Red Hat
BLK:200:403:200:200:200:HTM:501:200:200:HTM:HTM:200:400:400:400:400:404:405:404:200:200:501:501:403::Apache/1.2.6
# Apache/1.2.6 KK-NET wpp/1.0
HTM:200:200:200:200:200:HTM:200:200:200:HTM:HTM:200:400:400:400:400:404:403:403:200:200:501:501:403::Apache/1.2.6
HTM:302:200:200:302:302:HTM:302:302:302:HTM:HTM:302:302:302:302:400:200:405:200:200:200:501:501:302::Apache/1.2.6 Ben-SSL/1.16 FrontPage/3.0.4
HTM:200:200:200:200:200:HTM:501:200:200:HTM:HTM:200:400:400:400:400:405:405:405:200:200:501:501:200::Apache/1.2b6
HTM:200:200:200:200:200:HTM:501:200:200:HTM:HTM:200:400:400:400:400:405:405:405:200:200:501:501:403::Apache/1.2b7
HTM:200:200:200:200:200:HTM:501:200:200:HTM:HTM:200:400:400:400:400:404:405:404:200:200:501:501:302::Apache/1.2b10
#
HTM:302:HTM:200:302:302:HTM:501:302:HTM:HTM:HTM:302:HTM:HTM:HTM:302:411:411:401:501:501:501:501:---::WebSite/3.5.17
HTM:200:HTM:200:200:200:HTM:501:200:HTM:HTM:HTM:200:HTM:HTM:HTM:200:411:411:401:501:501:501:501:---::WebSite/3.5.17
200:200:HTM:200:200:200:HTM:501:200:HTM:HTM:HTM:200:HTM:HTM:HTM:200:411:411:401:501:501:501:501:---::WebSite/3.5.19
HTM:200:HTM:200:200:200:HTM:501:200:HTM:HTM:HTM:200:HTM:HTM:HTM:200:411:411:403:501:501:501:501:---::WebSite/3.5.19
# http://www.tnsoft.com -> IA WebMail Server
200:200:200:200:200:200:200:200:200:200:200:200:200:200:200:200:200:+++:200:200:200:200:200:200:+++::WebMail/1.0 [IA WebMail Server version 3.1?]
# Eudora
HTM:200:400:200:200:HTM:HTM:200:200:HTM:HTM:HTM:200:400:400:400:200:400:400:400:400:400:400:400:404::WorldMail-HTTPMA/6.1.19.0
## A every common Apache signature ##
# Apache/1.3.4 (Unix)
# Apache/1.3.6 (Unix)
# Apache/1.3.9 (Unix)
# Apache/1.3.9 (Unix) mod_perl/1.21
# Apache/1.3.9 (Unix)  (SuSE/Linux)
# Apache/1.3.12 (Unix)
# Apache/1.3.12 (Unix)  (SuSE/Linux)
# Apache/1.3.12 (Unix) mod_perl/1.24 ApacheJserv/1.1.2
# Apache/1.3.12 (Unix)  (Red Hat/Linux) PHP/3.0.15
# Apache/1.3.14 (Unix)  (Red-Hat/Linux) PHP/4.1.2 ApacheJServ/1.1.2
# Apache/1.3.14 (Unix)  (Red-Hat/Linux) PHP/3.0.18 mod_perl/1.23
# Apache/1.3.19 (Unix)
# Apache/1.3.20 (Unix)
# Apache/1.3.22 (Unix)  (Red-Hat/Linux) PHP/4.1.2
# Apache/1.3.22 (Unix)  (Red-Hat/Linux) mod_ssl/2.8.5 OpenSSL/0.9.6b
# Apache/1.3.22 (Unix)  (Red-Hat/Linux) mod_ssl/2.8.5 OpenSSL/0.9.6b DAV/1.0.2 PHP/4.0.6 mod_perl/1.26
# Apache/1.3.22 (Unix)  (Red-Hat/Linux) mod_ssl/2.8.7 OpenSSL/0.9.6d
# Apache/1.3.22 (Unix) PHP/4.3.2
# Apache/1.3.23 (Unix)  (Red-Hat/Linux)
# Apache/1.3.23 (Unix) PHP/4.1.2
# Apache/1.3.23 (Unix)  (Red-Hat/Linux) mod_ssl/2.8.7 OpenSSL/0.9.6b DAV/1.0.3 PHP/4.1.2 mod_perl/1.26
# Apache/1.3.24 (Unix) mod_jk
# Apache/1.3.24 (Unix)
# Oracle9iAS/9.0.2 Oracle HTTP Server
# Oracle9iAS/9.0.2.2.0 Oracle HTTP Server
# Oracle9iAS/9.0.3.1 Oracle HTTP Server
# Oracle HTTP Server Powered by Apache/1.3.12 (Unix) ApacheJServ/1.1 mod_perl/1.24
# Oracle HTTP Server Powered by Apache/1.3.19 (Unix) mod_fastcgi/2.2.10 mod_perl/1.25 mod_oprocmgr/1.0
# Oracle HTTP Server Powered by Apache/1.3.19 (Unix) mod_plsql/3.0.9.8.3b mod_ssl/2.8.1 OpenSSL/0.9.5a mod_fastcgi/2.2.10 mod_perl/1.25 mod_oprocmgr/1.0
# Oracle HTTP Server Powered by Apache/1.3.19 (Unix) mod_plsql/3.0.9.8.3c mod_fastcgi/2.2.10 mod_perl/1.25 mod_oprocmgr/1.0
# MS-IIS/4.0-3  (WNT)	[is this a fake?]
##HTM:200:200:200:200:200:HTM:501:200:200:HTM:HTM:200:400:400:+++:400:404:405:404:200:200:404:501:+++:^(Apache(/1\.3.(9|1[249]|2[0234])[^0-9].*)?|Oracle9iAS/9\.0\.[23].*|Oracle HTTP Server Powered by Apache/1\.3\.1[29].*)$:Apache/1.3.9 to 1.3.24
## Same as above but more precise ##
# IBM_HTTP_SERVER/1.3.19.2  Apache/1.3.20 (Unix)
# IBM_HTTP_SERVER/1.3.19  Apache/1.3.20 (Unix)
# IBM_HTTP_SERVER
# IBM_HTTP_Server/1.3.12.3 Apache/1.3.12 (Unix)
# IBM_HTTP_Server/1.3.12.4 Apache/1.3.12 (Unix)
# IBM_HTTP_Server/1.3.12.6 Apache/1.3.12 (Unix)
# IBM_HTTP_SERVER/1.3.19.1  Apache/1.3.20 (Unix)
# IBM_HTTP_SERVER/1.3.19.3  Apache/1.3.20 (Unix)
# IBM_HTTP_SERVER/1.3.19.4  Apache/1.3.20 (Unix)
# IBM_HTTP_SERVER/1.3.19.5  Apache/1.3.20 (Unix)
# Apache/1.3.22 (Unix) PHP/4.0.6 mod_perl/1.26 FrontPage/5.0.2.2623 AuthMySQL/2.20 mod_ssl/2.8.5 OpenSSL/0.9.6a
# Apache/1.3.12 (Unix) PHP/4.3.1 rus/PL29.4
# Apache/1.3.12 (Unix) ApacheJServ/1.1 mod_perl/1.22
# TBD: verify Apache/1.3.7-dev & Apache/1.3.12
# IBM_HTTP_Server/1.3.6.1 Apache/1.3.7-dev (Unix)
# IBM_HTTP_Server/1.3.6.1 Apache/1.3.7-dev (Unix) PHP/4.0.6
# IBM_HTTP_Server/1.3.6.2 Apache/1.3.7-dev (Unix)
# IBM_HTTP_Server/1.3.6.2 Apache/1.3.7-dev (Unix) PHP/4.0.4
# Apache/1.3.19 (Unix) Resin/1.2.2 mod_ssl/2.8.3 OpenSSL/0.9.6a
# Oracle HTTP Server Powered by Apache/1.3.19 (Unix) mod_fastcgi/2.2.10 mod_perl/1.25 mod_oprocmgr/1.0
# Oracle9iAS/9.0.2.3.0 Oracle HTTP Server
# Oracle9iAS/9.0.2 Oracle HTTP Server
# Apache/1.3.12p (Unix)
HTM:200:200:200:200:200:HTM:501:200:200:HTM:HTM:200:400:400:400:400:404:405:404:200:200:404:501:403:^(IBM_HTTP_SERVER$|Oracle9iAS/9\.0\.2[0-9.]* Oracle HTTP Server|(Oracle HTTP Server Powered by +|IBM_HTTP_SERVER/1\.3\.1?[0-9](\.[0-9])? +)?Apache/1\.3\.(1[2-9]|2[0-2])[a-z]? \(Unix\)):Apache/1.3.12-22 (Unix) [may be IBM_HTTP_SERVER/1.3.x or Oracle HTTP Server]
# Oracle9iAS/9.0.2.1.0 Oracle HTTP
# IBM_HTTP_SERVER/1.3.19.5  Apache/1.3.20 (Unix)
# Apache-AdvancedExtranetServer/1.3.23 (Mandrake Linux/4mdk) PHP/4.1.2
# Apache/1.3.20 Sun Cobalt (Unix) Chili!Soft-ASP/3.6.2 mod_ssl/2.8.4 OpenSSL/0.9.6b PHP/4.0.6 mod_auth_pam_external/0.1 FrontPage/4.0.4.3 mod_perl/1.25
# Apache/1.3.20 Sun Cobalt (Unix) mod_ssl/2.8.4 OpenSSL/0.9.6b PHP/4.0.6 mod_auth_pam_external/0.1 FrontPage/4.0.4.3 mod_perl/1.25
# Apache/1.3.20 Sun Cobalt (Unix) mod_throttle/3.1.2 Chili!Soft-ASP/3.6.2 mod_ssl/2.8.4 OpenSSL/0.9.6b PHP/4.1.2 mod_auth_pam_external/0.1 FrontPage/4.0.4.3 mod_perl/1.25
# IBM_HTTP_SERVER/1.3.19.2  Apache/1.3.20 (Unix)
# IBM_HTTP_SERVER/1.3.19.2  Apache/1.3.20 (Unix) PHP/4.2.2
# IBM_HTTP_SERVER/1.3.19.3  Apache/1.3.20 (Unix)
# IBM_HTTP_SERVER/1.3.19.5  Apache/1.3.20 (Unix)
# IBM_HTTP_SERVER/1.3.19  Apache/1.3.20 (Unix)
# Apache/1.3.23 (Unix)  (Red-Hat/Linux) mod_watch/3.17 mod_ssl/2.8.12 OpenSSL/0.9.6b DAV/1.0.3 PHP/4.1.2 mod_perl/1.26
# Apache/1.3.19 Ben-SSL/1.44 (Unix) PHP/4.0.3pl1
# Apache/1.3.24 Ben-SSL/1.48 (Unix) PHP/3.0.18
# Apache/1.3.22 (Unix)  (Red-Hat/Linux) mod_jk/1.2.0 mod_perl/1.24_01 PHP/4.1.1 FrontPage/5.0.2 mod_ssl/2.8.5 OpenSSL/0.9.6b
# Apache/1.3.12 (Unix) PHP/4.0.4pl1
# Apache/1.3.12 (Unix) PHP/3.0.15
# Apache/1.3.17 (Unix) PHP/4.3.1
#  Apache/1.3.19 (Unix) Resin/2.1.0
HTM:200:200:200:200:200:HTM:501:200:200:HTM:HTM:200:400:400:400:400:404:405:404:200:200:404:501:200:^(Oracle9iAS/9\.0\.2|(IBM_HTTP_SERVER/1\.3\.19(\.[2-5])? )?Apache(-AdvancedExtranetServer)?/1\.3\.(1[2-9]|2[0-4]) [A-Za-z ]*\(Unix|Mandrake Linux/4mdk|Red-Hat/Linux\)):Apache/1.3.12-24 (Unix) [might be IBM_HTTP_SERVER/1.3.19.x] -or- Oracle9iAS/9.0.2.x
# Slightly different
xxx:200:200:200:200:200:xxx:501:200:200:HTM:xxx:200:400:400:400:400:404:405:404:200:200:404:501:200::IBM_HTTP_SERVER/1.3.19.2  Apache/1.3.20 (Unix)
HTM:200:200:200:200:200:HTM:501:200:200:HTM:HTM:200:400:400:400:400:404:405:---:200:200:404:501:403::IBM_HTTP_SERVER/1.3.19.5  Apache/1.3.20 (Unix)
# Apache-AdvancedExtranetServer/1.3.23 (Mandrake Linux/4mdk) PHP/4.1.2
# Apache-AdvancedExtranetServer/1.3.23 (Mandrake Linux/4mdk) mod_perl/1.26
##HTM:200:403:200:200:200:HTM:501:200:200:HTM:HTM:200:400:400:+++:400:404:405:404:200:200:404:501:+++::Apache-AdvancedExtranetServer/1.3.23 (Mandrake Linux/4mdk)
# More precise!
HTM:200:403:200:200:200:HTM:501:200:200:HTM:HTM:200:400:400:400:400:404:405:404:200:200:404:501:403::Apache/1.3.20a (NETWARE) mod_jk
# Apache-AdvancedExtranetServer/1.3.23 (Mandrake Linux/4mdk) mod_ssl/2.8.7 OpenSSL/0.9.6c PHP/4.1.2
# Apache-AdvancedExtranetServer/1.3.23 (Mandrake Linux/4mdk) PHP/4.1.2
# Apache/1.3.20 Sun Cobalt (Unix) PHP/4.0.4 mod_auth_pam_external/0.1 FrontPage/4.0.4.3 mod_ssl/2.8.4 OpenSSL/0.9.6b mod_perl/1.25
HTM:200:403:200:200:200:HTM:501:200:200:HTM:HTM:200:400:400:400:400:404:405:404:200:200:404:501:200:^Apache(-AdvancedExtranetServer)?/1\.3\.2[0-3]:Apache/1.3.20-23 (Unix)
# Apache-AdvancedExtranetServer/1.3.23 (Mandrake Linux/4.2mdk) mod_ssl/2.8.7 OpenSSL/0.9.6c PHP/4.1.2
# Apache-AdvancedExtranetServer/1.3.26 (Mandrake Linux/6.3.90mdk) DAV/1.0.3 PHP/4.2.3
# Apache-AdvancedExtranetServer/1.3.26 (Mandrake Linux/6mdk) sxnet/1.2.4 mod_ssl/2.8.10 OpenSSL/0.9.6g PHP/4.2.3
HTM:200:403:200:400:400:HTM:400:400:200:HTM:HTM:200:400:400:400:400:404:405:404:200:200:404:501:200:^Apache(-AdvancedExtranetServer)?/1\.3\.2[3-6]:Apache/1.3.23-26 (Linux)
# Apache-AdvancedExtranetServer/1.3.28 (Mandrake Linux/3.1.92mdk)
# Apache-AdvancedExtranetServer/1.3.28 (Mandrake Linux/3.1.92mdk) mod_fastcgi/2.4.0 sxnet/1.2.4 mod_ssl/2.8.15 OpenSSL/0.9.7b PHP/4.3.3
# Apache/1.3.29 (Debian GNU/Linux) PHP/4.3.3 mod_ssl/2.8.14 OpenSSL/0.9.7b
# Apache/1.3.27 (Unix)  (Red-Hat/Linux) mod_ssl/2.8.12 OpenSSL/0.9.6b DAV/1.0.3 PHP/4.1.2 mod_perl/1.26
# Apache/1.3.27  (Unix) (Red-Hat/Linux) mod_watch/3.12 mod_throttle/3.1.2  mod_gzip/1.3.19.1a mod_auth_pam/1.0a mod_ssl/2.8.11 OpenSSL/0.9.6j  PHP/4.3.3 mod_perl/1.26 FrontPage/5.0.2.2510
# Apache/1.3.27 (Unix)   [on QNX without mod_fastcgi]
# Apache/1.3.27 (Unix) Debian GNU/Linux [on Xandros]
# IBM_HTTP_SERVER/1.3.26.2  Apache/1.3.26 (Unix)
# Apache/1.3.31 (Unix) PHP/4.3.6
# Apache/1.3.31 (Unix) mod_perl/1.29 [mod_auth_external, mod_perl and HTML::Mason on Slackware Linux 9.1]
# Apache/1.3.32 (Unix) mod_jk/1.2.6 mod_mono/1.0.1 mod_auth_passthrough/1.8 mod_log_bytes/1.2 mod_bwlimited/1.4 PHP/4.3.9 FrontPage/5.0.2.2634a mod_ssl/2.8.21 OpenSSL/0.9.7a
# Apache/1.3.33 (Unix) mod_perl/1.29
# Apache/1.3.33 (Unix) Resin/3.0.9 mod_auth_passthrough/1.8 mod_log_bytes/1.2 mod_bwlimited/1.4 FrontPage/5.0.2.2634a mod_ssl/2.8.22 OpenSSL/0.9.7a PHP-CGI/0.1b
HTM:200:200:200:400:400:HTM:501:400:200:HTM:HTM:200:400:400:400:400:404:405:404:200:200:404:501:200:^(IBM_HTTP_SERVER|Apache(-AdvancedExtranetServer)?)(/1\.3(\.(2[789]|3[0-3]).*)?)?$:Apache/1.3.27-33 (Unix)
HTM:301:200:200:400:400:HTM:301:400:301:HTM:HTM:301:400:400:400:400:404:405:404:200:200:404:501:301::Apache/1.3.33 (Unix) PHP/5.1.1 mod_perl/1.29
HTM:200:200:200:400:400:HTM:200:400:200:HTM:HTM:200:400:400:400:400:404:405:404:200:403:404:501:403::Apache/1.3.31 (Unix) mod_ssl/2.8.18 OpenSSL/0.9.7d mod_gzip/1.3.26.1a mod_security/1.5 PHP/4.3.8
---:200:200:200:400:400:---:501:400:200:---:---:200:400:400:400:---:404:405:404:200:403:404:501:200::Apache-AdvancedExtranetServer/1.3.28 (Mandrake Linux/3.1.92mdk) mod_fastcgi/2.2.12 sxnet/1.2.4 mod_ssl/2.8.15 OpenSSL/0.9.7b PHP/4.3.3
HTM:200:200:200:400:400:HTM:501:400:200:HTM:HTM:200:400:302:+++:+++:404:405:404:200:200:404:501:+++::Apache/1.3.27 (Red-Hat/Linux)
HTM:200:501:200:400:400:400:400:400:---:HTM:---:200:400:400:400:400:404:405:404:501:501:404:501:200::Apache/1.3.28 (Unix) dynamicScale/2.0.3 PHP/4.3.3
HTM:200:501:200:400:400:400:400:400:200:HTM:HTM:200:400:400:400:400:404:405:404:501:501:501:501:403::Apache/1.3.26
# Apache on Debian GNU/Linux
HTM:200:200:200:400:400:HTM:200:400:200:HTM:HTM:200:400:400:+++:+++:404:405:404:200:200:404:501:400::Apache/1.3.27 (Unix) Debian GNU/Linux
# More precise
# Apache/1.3.28 (Unix) Resin/2.1.8 PHP/4.3.2 mod_ssl/2.8.15 OpenSSL/0.9.7b
# Apache/1.3.28 Ben-SSL/1.49 (Unix) Resin/2.1.13
HTM:200:200:200:400:400:HTM:200:400:200:HTM:HTM:200:400:400:400:400:404:405:404:200:200:404:501:400:^Apache/1\.3\.28 .*\(Unix\):Apache/1.3.28 (Unix)
HTM:200:200:200:400:---:HTM:200:400:200:HTM:HTM:200:400:400:400:400:404:405:404:200:403:404:501:+++::Apache/1.3.27 (Unix) Debian GNU/Linux
HTM:200:200:200:400:400:HTM:400:400:200:HTM:HTM:200:400:400:400:400:404:403:403:200:200:403:501:200::Apache/1.3.26 (Unix) Debian GNU/Linux PHP/4.1.2
HTM:200:200:200:400:400:HTM:400:400:200:HTM:HTM:200:400:400:400:400:200:200:200:200:200:200:200:200::Apache/1.3.26 (Unix) Debian GNU/Linux
HTM:200:200:200:400:400:HTM:400:400:200:HTM:HTM:200:400:400:400:400:200:405:200:200:200:200:501:200::Apache/1.3.26 (Unix)
# An older signature also matched Apache/1.3.27 (Unix) Debian GNU/Linux
# Apache/1.3.29 (Unix) PHP/4.3.4
# Apache/1.3.27 (Unix)  (Red-Hat/Linux) mod_ssl/2.8.12 OpenSSL/0.9.6b DAV/1.0.2 mod_perl/1.24_01
# Apache/1.3.28 (Linux/SuSE) mod_perl/1.28
# Apache/1.3.31 Ben-SSL/1.53 (Unix)
HTM:200:200:200:400:400:HTM:501:400:200:HTM:HTM:200:400:400:400:400:404:405:404:200:403:404:501:200:^Apache/1\.3\.(2[7-9]|3[01]) \(Unix|Linux/SuSE|[A-Z ]*Linux[a-z0-9 /]*):Apache/1.3.27-29 (Unix)
xxx:200:403:200:400:400:xxx:501:400:200:HTM:xxx:200:400:400:+++:+++:404:405:404:200:403:404:501:+++::Apache/1.3.28 (FreeBSD/locked)
HTM:200:200:200:400:400:HTM:501:400:200:HTM:HTM:200:400:301:301:400:404:405:404:200:200:404:501:403::Apache/1.3.28 (Unix) mod_deflate/1.0.19 mod_accel/1.0.30
HTM:200:200:200:400:400:HTM:501:400:200:---:HTM:200:400:400:400:400:404:403:403:200:200:404:501:200::Apache/1.3.29 (Unix) mod_auth_passthrough/1.8 mod_log_bytes/1.2 mod_bwlimited/1.2 PHP/4.3.3 FrontPage/5.0.2.2634 mod_ssl/2.8.16 OpenSSL/0.9.6b
HTM:200:200:200:400:400:HTM:501:400:200:HTM:HTM:200:404:301:301:400:404:403:403:200:200:404:501:403::Apache/1.3.29 (Unix) FrontPage/5.0.2.2634 mod_ssl/2.8.16 OpenSSL/0.9.6k
HTM:500:200:200:400:400:HTM:500:400:500:HTM:HTM:500:404:301:301:400:VER:405:VER:200:200:VER:501:500::Apache/1.3.29 (Unix)
HTM:200:200:200:400:400:HTM:501:400:200:HTM:HTM:200:404:301:301:400:VER:405:VER:200:200:VER:501:200::Apache/1.3.29 (Unix)
# Apache/1.3.29 (Unix) PHP/4.3.4 mod_throttle/3.1.2 mod_ssl/2.8.16 OpenSSL/0.9.7c
# Apache/1.3.31 (Debian GNU/Linux) mod_gzip/1.3.26.1a PHP/4.3.9-1 mod_ssl/2.8.19 OpenSSL/0.9.7d mod_perl/1.29
# Apache/1.3.32 (Unix) PHP/4.3.4 mod_throttle/3.1.2 mod_ssl/2.8.21 OpenSSL/0.9.7e
HTM:200:403:200:400:400:HTM:200:400:200:HTM:HTM:200:400:400:400:400:404:405:404:200:200:404:501:200:^Apache/1\.3\.(29|3[0-2]) \(Unix|[A-Za-z /]*Linux\):Apache/1.3.29-32 (Unix)
HTM:500:200:200:400:400:HTM:500:400:500:HTM:HTM:500:400:400:400:400:404:405:404:200:200:404:501:403::Apache/1.3.31 (Unix) FrontPage/5.0.2.2635 mod_ssl/2.8.17 OpenSSL/0.9.7c
HTM:200:400:200:400:400:HTM:501:400:200:HTM:HTM:200:400:400:400:400:404:405:404:200:200:404:501:403::Apache/1.3.31 (Unix) mod_fastcgi/2.4.2 FrontPage/5.0.2.2635 mod_jk/1.2.5
HTM:200:200:200:400:400:HTM:200:400:200:HTM:HTM:200:400:400:400:400:302:405:302:200:200:302:302:200::Apache/1.3.31 (Unix) mod_auth_passthrough/1.8 mod_log_bytes/1.2 mod_bwlimited/1.4 PHP/4.3.8 FrontPage/5.0.2.2634a mod_ssl/2.8.19 OpenSSL/0.9.6b
HTM:200:200:200:400:400:HTM:501:400:200:HTM:HTM:200:400:400:400:400:404:403:403:200:200:403:501:200::Apache/1.3.31 (Debian GNU/Linux)
# Apache/1.3.29 (Unix) ApacheJServ/1.1.2 PHP/4.3.4 mod_throttle/2.11 FrontPage/5.0.2.2634 Rewrit/1.1a
# Apache/1.3.31 (Unix) mod_auth_passthrough/1.8 mod_log_bytes/1.2 mod_bwlimited/1.4 PHP/4.3.8 FrontPage/5.0.2.2634a mod_ssl/2.8.19 OpenSSL/0.9.7a
HTM:200:200:200:400:400:HTM:200:400:200:HTM:HTM:200:400:400:400:400:404:403:403:200:200:404:501:200:^Apache/1\.3\.(29|3[01]) \(Unix\):Apache/1.3.29-31 (Unix)
# Apache/1.3.29 (Unix) mod_auth_passthrough/1.8 mod_log_bytes/1.2 mod_bwlimited/1.4 PHP/4.3.4 FrontPage/5.0.2.2634 mod_ssl/2.8.16 OpenSSL/0.9.6b
# Apache/1.3.29 (Unix)  (PLD/Linux) mod_ssl/2.8.15 OpenSSL/0.9.6j mod_fastcgi/2.2.12 PHP/4.2.3 mod_perl/1.27
# Apache/1.3.29 (Unix) mod_ssl/2.8.16 OpenSSL/0.9.7c PHP/4.3.4
# Apache/1.3.28 (Unix) PHP/4.3.3
# Apache/1.3.31 (Unix) Mya/1.2 PHP/4.3.8 mod_ssl/2.8.18 OpenSSL/0.9.7d
# Apache/1.3.27 (Unix) PHP/4.2.3
# Apache/1.3.27 (Unix) PHP/4.2.2 [xxx -> htm]
# Apache/1.3.27 (ALT Linux/alt13) PHP/4.3.1-dev/ALT rus/PL30.16
# Apache/1.3.29 Sun Cobalt (Unix) mod_jk mod_ssl/2.8.16 OpenSSL/0.9.6m PHP/4.2.3 FrontPage/5.0.2.2510 mod_auth_pam_external/0.1 mod_perl/1.26
# Apache/1.3.32 (Unix) mod_gzip/1.3.19.1a PHP/4.3.9 mod_ssl/2.8.21 OpenSSL/0.9.6m
# Apache/1.3.33 (Unix) mod_ssl/2.8.22 OpenSSL/0.9.7a
HTM:200:200:200:400:400:HTM:200:400:200:HTM:HTM:200:400:400:400:400:404:405:404:200:200:404:501:200:^Apache/1\.3\.(2[7-9]|3[0-3]) [a-zA-Z ]*\(Unix|[A-Za-z/ ]*Linux[A-Za-z0-9/ ]*\):Apache/1.3.27-33 (Unix) [PHP/4?]
# Apache/1.3.27 (Unix) Resin/2.1.6 mod_throttle/3.1.2
# Apache/1.3.27 (Unix) PHP/4.2.2
# Apache/1.3.28 (Unix) Resin/2.1.10 mod_throttle/3.1.2 mod_ssl/2.8.15 OpenSSL/0.9.7a
xxx:200:200:200:400:400:xxx:200:400:200:xxx:xxx:200:400:400:400:400:404:405:404:200:200:404:501:200:^Apache/1\.3\.2[78] \(Unix\): Apache/1.3.27-28 (Unix)
# Although cover the previous case (should be improved)
HTM:200:200:200:400:400:HTM:200:400:200:HTM:HTM:200:400:400:+++:+++:404:405:404:200:200:404:501:+++::Apache/1.3.28
---:302:200:200:302:302:---:501:302:302:HTM:---:302:400:400:400:400:404:405:405:200:403:405:501:302::Apache/2.0.48 (Unix) Debian GNU/Linux
HTM:200:200:200:400:400:HTM:501:400:200:HTM:HTM:200:400:400:400:400:302:302:302:302:200:302:302:200::Apache/1.3.33 (ALT Linux/alt1) PHP/4.3.10-ALT
# Apache/2.0.48 with full modules support, compiled with openssl 0.9.7c Kernel 2.4.24 on RedHat 9.0 distribution
HTM:200:200:200:200:200:HTM:501:200:200:HTM:HTM:200:400:400:400:400:404:405:405:200:403:405:405:200::Apache/2.0.48 (Unix) [RedHat 9.0]
# Fedora core release 1 5Yarrow)
# php-4.3.4-1.1, php-ldap-4.3.4-1.1, php-mysql-4.3.4-1.1, php-imap-4.3.4-1.1, httpd-2.0.48-1.2, mod_ssl-2.0.48-1.2, mod_python-3.0.4-0.1
# mod_auth_mysql-20030510-3, mod_perl-1.99_12-2
xxx:200:200:200:200:200:xxx:200:200:200:xxx:xxx:200:302:302:302:400:404:302:302:200:200:302:302:200::Apache/2.0.48 (Fedora)
# Apache 2.0.48 on Solaris 8
HTM:200:200:200:200:200:HTM:501:200:200:HTM:HTM:200:400:400:400:---:404:405:405:200:200:405:501:---::Apache/2.0.48 (Unix) [Solaris 8]
#
HTM:200:200:200:200:200:HTM:403:200:200:HTM:HTM:200:400:400:400:400:404:403:403:200:200:403:403:200::Apache/2.0.40 (Red Hat Linux)
XML:200:200:200:200:200:XML:200:200:200:XML:XML:200:400:400:400:400:200:200:200:200:200:200:200:200::Apache/2.0.40 (Red Hat Linux)
HTM:200:200:200:200:200:HTM:501:200:200:HTM:HTM:200:302:301:301:400:302:405:405:200:200:405:405:403::Apache/2.0.46 (Red Hat)
# Apache/2.0.46 (Red Hat)
# Apache/2.0.46 (Unix) mod_perl/1.99_09 Perl/v5.8.0 mod_ssl/2.0.46 OpenSSL/0.9.7a DAV/2 FrontPage/5.0.2.2634 PHP/4.3.3 mod_gzip/2.0.26.1a
HTM:200:200:200:200:200:HTM:501:200:200:HTM:HTM:200:400:400:400:400:302:405:405:200:200:405:405:200:^Apache/2\.0\.46 \(Unix|Red Hat|[A-Za-z /]*Linux\):Apache/2.0.46 (Unix)
HTM:200:200:200:200:200:HTM:501:200:200:XML:HTM:200:400:400:400:400:404:403:403:200:200:405:405:200::Apache/2.0.40 (Red Hat Linux)
HTM:200:200:200:200:200:HTM:501:200:200:HTM:HTM:200:200:400:400:400:200:405:405:200:200:405:405:200::Apache/2.0.40 (Red Hat Linux)
# Apache/2.0.46 (Red Hat)
# Apache/2.0.48 (Fedora)
HTM:200:200:200:200:200:HTM:501:200:200:HTM:HTM:200:400:400:400:400:404:405:405:200:200:405:405:302:^Apache/2\.0\.4[6-8] \(Red Hat|Fedora\):Apache/2.0.46-48 (Red Hat)
HTM:200:200:200:200:200:HTM:501:200:200:XML:HTM:200:400:400:400:400:302:405:405:200:200:405:405:200::Apache/2.0.40 (Red Hat Linux)
HTM:200:200:200:200:200:HTM:501:200:200:HTM:HTM:200:400:400:400:400:404:403:403:200:200:405:405:200::Apache/2.0.40 (Red Hat Linux) mod_perl/1.99_07-dev Perl/v5.8.0 PHP/4.2.2 mod_ssl/2.0.40 OpenSSL/0.9.7a DAV/2 JRun/4.0
XML:200:200:200:200:200:XML:200:200:200:XML:XML:200:400:400:400:400:404:405:405:200:200:405:405:200::Apache/2.0.40 (Red Hat Linux)
# Apache/2.0.48 (Unix) PHP/4.3.3
# Apache/2.0.48 (Fedora) PHP/4.3.4
HTM:200:200:200:200:200:HTM:501:200:200:HTM:HTM:200:400:400:400:400:302:405:405:200:200:405:501:200:^Apache/(2\.0\.48 \(Unix|Fedora|Linux\) PHP/4\.3\.[34]:Apache/2.0.48 (Unix) PHP/4.3.x
XML:200:200:200:200:200:XML:501:200:200:HTM:XML:200:400:400:400:400:404:201:404:200:200:404:405:200::Apache/2.0.50 (Debian GNU/Linux) DAV/2 SVN/1.0.5 mod_python/3.1.3 Python/2.3.4
# Apache/2.0.50 (Unix) PHP/4.3.7
# Apache/2.0.52 (Gentoo/Linux)
# Apache/2.0.54 (Gentoo/Linux)
HTM:200:200:200:200:200:HTM:501:200:200:HTM:HTM:200:400:400:400:400:404:405:405:200:403:405:501:200:^Apache(/2\.0\.5[0-4] \((Unix|[a-zA-Z/]*Linux).*)?$:Apache/2.0.50-54 (Unix)
# Apache/2.0.40 (Red Hat Linux)
# Apache/2.0.48 (Linux/SuSE)
# Apache/2.0.48 (Unix) mod_ssl/2.0.48 OpenSSL/0.9.7c PHP/4.3.4
# Apache/2.0.49 (Linux/SuSE) [SuSE Linux 9.1]
# Apache/2.0.52 (NETWARE) mod_jk/1.2.6a
HTM:200:200:200:200:200:HTM:501:200:200:XML:HTM:200:400:400:400:400:404:405:405:200:200:405:501:200:^Apache/2\.0\.(4[0-9]|5[0-2]) \(Unix|NETWARE|[A-Za-z ]*Linux[/A-Za-z ]*\):Apache/2.0.40-52 on Unix or NETWARE
# Same as above, less precise
HTM:200:200:200:200:200:HTM:501:200:200:XML:HTM:200:400:400:400:400:404:405:405:200:200:405:501:+++::Rational_Web_Platform [Clearcase Webserver]
# Apache/2.0.49 (Unix) PHP/4.3.7
# Apache/2.0.47 (Unix) FrontPage/5.0.2.2626
HTM:200:200:200:200:200:HTM:501:200:200:HTM:HTM:200:400:400:400:400:200:405:405:200:200:405:501:200:^Apache/2\.0\.4[7-9] \(Unix\):Apache/2.0.47-49 (Unix)
HTM:200:200:200:200:200:HTM:200:200:200:HTM:HTM:200:400:400:400:400:404:403:403:200:200:405:501:200::Apache/2.0.49 (Linux/SuSE)
400:200:400:200:400:400:400:400:400:400:400:400:200:400:400:400:200:404:405:405:200:200:405:400:403::Apache/2.0.49 (Unix) mod_python/3.1.3 Python/2.3.4
# httpd-2.0.52-9.ent on RedHat Enterprise Server v4 ES 2.6.9-5.ELsmp 
HTM:404:200:200:404:404:HTM:404:404:404:HTM:HTM:404:400:400:400:400:404:405:405:200:200:405:405:404::Apache/2.0.52-9 [w/ PHP/4.3.9 on Redhat ES]
HTM:200:200:200:200:200:HTM:200:200:200:HTM:HTM:200:400:400:400:400:404:405:405:200:200:405:501:400::Apache/2.0.49 (Unix) mod_ssl/2.0.49 OpenSSL/0.9.7d Resin/3.0.7 JRun/4.0
# 
HTM:200:200:200:200:200:HTM:501:200:200:HTM:HTM:200:400:400:400:400:200:405:200:200:200:200:501:403::Apache/1.3.9 (Unix) DAV/0.9.16 AuthMySQL/2.20 PHP/3.0.12 mod_perl/1.21 mod_ssl/2.4.5 OpenSSL/0.9.4
# Apache 1.3.9 on Linux 2.2.16 (gcc version 2.7.2.3)
HTM:200:403:200:200:200:HTM:501:200:200:HTM:HTM:200:400:400:400:400:404:405:404:200:403:404:501:+++::Apache/1.3.9 (Unix) PHP/4.2.3 PHP/3.0.18
# Linux 2.2.19-6.2.1 (RedHat 6.2) Apache 1.3.29 modssl 2.8.16 openssl 0.9.7c
HTM:200:200:200:400:400:HTM:501:400:200:HTM:HTM:200:400:400:400:400:200:405:200:200:403:200:501:200::Apache/1.3.29 (RedHat 6.2) modssl/2.8.16 OpenSSL/0.9.7c
HTM:200:403:200:400:400:HTM:HTM:HTM:HTM:HTM:HTM:200:500:500:500:400:404:405:404:200:200:404:501:200::Apache/1.3.29 (Unix)
# Apache/1.3.29 (Unix) PHP/4.3.4 mod_perl/1.29
# Apache/1.3.28 (Unix) PHP/4.3.3 mod_ssl/2.8.15 OpenSSL/0.9.7b
# Apache/1.3.4 (Unix)
# Apache/1.3.29 (Unix)  (PLD/Linux) mod_fastcgi/2.2.12 PHP/4.2.3
# Apache/1.3.29 (Unix) mod_perl/1.29 PHP/4.3.4 mod_ssl/2.8.16 OpenSSL/0.9.7c
# Apache/1.3.31 (Unix) Midgard/1.5.0/SG PHP/4.3.9
HTM:200:200:200:400:400:HTM:501:400:200:HTM:HTM:200:400:400:400:400:404:405:404:200:200:404:501:+++:^Apache/1\.3\.(4|2[89]|3[01]) \(Unix\):Apache/1.3.4-31 (Unix)
# More precise
HTM:200:200:200:400:400:HTM:501:400:200:HTM:HTM:200:400:400:400:400:404:405:404:200:200:404:501:400::Apache/1.3.27 (Unix) Resin/2.1.10 mod_ssl/2.8.14 OpenSSL/0.9.7b
# Apache/1.3.27 (Unix)  (Red-Hat/Linux) mod_jk/1.2.0 mod_perl/1.26 PHP/4.3.3 FrontPage/5.0.2 mod_ssl/2.8.12 OpenSSL/0.9.6b
# Apache/1.3.27 (Unix)  (Red-Hat/Linux) mod_perl/1.26 PHP/4.3.3 FrontPage/5.0.2 mod_ssl/2.8.12 OpenSSL/0.9.6b
HTM:200:200:200:400:400:HTM:501:400:200:HTM:HTM:200:400:400:400:400:404:405:404:200:200:404:501:302::Apache/1.3.27 (Unix)  (Red-Hat/Linux)
# Apache/1.3.29 (Unix) mod_perl/1.29 PHP/4.3.4 mod_ssl/2.8.16 OpenSSL/0.9.7c
# Apache/1.3.29 (Unix) PHP/4.3.2
HTM:403:200:403:400:400:HTM:501:400:403:HTM:HTM:403:400:400:400:400:404:405:404:200:200:404:501:403:^Apache/1\.3\.29 \(Unix\) .*PHP/4\.3\.[2-4]:Apache/1.3.29 (Unix) PHP/4.3.2-4
HTM:200:200:302:200:200:HTM:501:200:200:HTM:HTM:200:400:400:+++:400:404:403:403:200:200:404:501:+++::Apache/1.3.11 (Unix) mod_perl/1.21 AuthMySQL/2.20
# Apache/1.3.11 (Unix) mod_fastcgi/2.2.2 ApacheJServ/1.1 FrontPage/4.0.4.3 mod_perl/1.21
# IBM_HTTP_SERVER/1.3.19.1  Apache/1.3.20 (Unix)
# Apache/1.3.19 (Unix) FrontPage/5.0.2.2510
# Apache/1.3.6 (Unix) mod_ssl/2.3.5 OpenSSL/0.9.3a
HTM:200:200:200:200:200:HTM:501:200:200:HTM:HTM:200:400:400:400:400:404:403:403:200:200:404:501:403:^Apache/1\.3\.([6-9]|1[1-9](\.[0-9]+)?) \(Unix\):Apache/1.3.6-19 (Unix)
HTM:200:200:200:200:200:HTM:501:200:200:HTM:HTM:200:400:400:400:400:404:405:404:200:403:404:501:200::Apache/1.3.19 (Unix) PHP/4.3.4 mod_gzip/1.3.19.1a Resin/2.1.0
# Apache/1.3.19 (Unix)  (SuSE/Linux) PHP/4.1.2 mod_perl/1.25 mod_throttle/3.0 mod_layout/1.0 mod_fastcgi/2.2.2 mod_dtcl
# Apache/1.3.12 (Unix) PHP/4.3.0
HTM:200:200:200:200:200:HTM:501:200:200:HTM:HTM:200:400:400:400:400:404:403:403:200:200:404:501:200:^Apache/1\.3\.1[2-9] \(Unix\):Apache/1.3.12-19 (Unix)
HTM:500:500:500:500:500:HTM:500:500:HTM:HTM:HTM:500:500:500:500:500:200:500:500:500:500:500:500:500::IBM_HTTP_Server/1.3.12.2 Apache/1.3.12 (Unix)
HTM:200:200:200:200:200:HTM:200:200:200:HTM:HTM:200:400:400:400:400:302:405:302:200:200:302:501:403::Apache/1.3.12 (Unix) PHP/4.2.1 FrontPage/4.0.4.3
#### The same server returns two different signatures
---:200:200:200:400:400:---:200:400:200:---:---:200:400:301:301:400:404:405:404:200:200:403:501:200::Apache/1.3.27 (Unix) Debian GNU/Linux mod_ssl/2.8.14 OpenSSL/0.9.7b Midgard/1.5.0/SG PHP/4.2.3
---:200:200:200:400:400:---:200:400:200:---:---:200:400:301:301:400:404:405:404:200:200:404:501:200::Apache/1.3.27 (Unix) Debian GNU/Linux mod_ssl/2.8.14 OpenSSL/0.9.7b Midgard/1.5.0/SG PHP/4.2.3
####
# Unreliable signature
xxx:400:405:301:400:400:xxx:405:400:400:xxx:xxx:400:400:400:400:400:405:405:405:405:200:405:405:400::Apache/1.3.28 (Unix) mod_forward_0_3 [aka reverse proxy]
# Cobalt
HTM:302:200:200:302:302:HTM:302:302:302:HTM:HTM:302:400:400:400:400:404:405:404:200:200:501:501:302::Apache/1.3.3 Cobalt (Unix)  (Red Hat/Linux)
# Apache/1.3.12 Cobalt (Unix) mod_ssl/2.6.4 OpenSSL/0.9.5a mod_auth_pam/1.0a FrontPage/4.0.4.3 mod_perl/1.24
# Apache/1.3.12 Cobalt (Unix) mod_ssl/2.6.4 OpenSSL/0.9.5a PHP/4.0.1pl2 mod_auth_pam/1.0a FrontPage/4.0.4.3 mod_perl/1.24
# Apache/1.3.12 Cobalt (Unix) mod_ssl/2.6.4 OpenSSL/0.9.5a PHP/4.0.3pl1 mod_auth_pam/1.0a FrontPage/4.0.4.3 mod_perl/1.24
# Apache/1.3.12 Cobalt (Unix) mod_ssl/2.6.4 OpenSSL/0.9.5a PHP/4.1.2 mod_auth_pam/1.0a FrontPage/4.0.4.3 mod_perl/1.24
# Apache/1.3.20 Sun Cobalt (Unix) mod_ssl/2.8.4 OpenSSL/0.9.6b PHP/4.1.2 mod_auth_pam_external/0.1 FrontPage/4.0.4.3 mod_perl/1.25
# Apache/1.3.20 Sun Cobalt (Unix) mod_ssl/2.8.4 OpenSSL/0.9.6b PHP/4.3.3 mod_auth_pam_external/0.1 FrontPage/4.0.4.3 mod_perl/1.25
# Apache/1.3.20 Sun Cobalt (Unix) Chili!Soft-ASP/3.6.2 mod_ssl/2.8.4 OpenSSL/0.9.6b mod_auth_pam_external/0.1 FrontPage/4.0.4.3 mod_perl/1.25
# Apache/1.3.20 Sun Cobalt (Unix) Chili!Soft-ASP/3.6.2 mod_ssl/2.8.4 OpenSSL/0.9.6b PHP/4.0.6 mod_auth_pam_external/0.1 FrontPage/4.0.4.3 mod_perl/1.25
# Apache/1.3.20 Sun Cobalt (Unix) Chili!Soft-ASP/3.6.2 mod_ssl/2.8.4 OpenSSL/0.9.6b PHP/4.1.2 mod_auth_pam_external/0.1 FrontPage/4.0.4.3 mod_perl/1.25
# Apache/1.3.20 Sun Cobalt (Unix) Chili!Soft-ASP/3.6.2 mod_ssl/2.8.4 OpenSSL/0.9.6b PHP/4.3.2 mod_auth_pam_external/0.1 FrontPage/4.0.4.3 mod_perl/1.25
# Apache/1.3.20 Sun Cobalt (Unix) Chili!Soft-ASP/3.6.2 mod_ssl/2.8.4 OpenSSL/0.9.6b PHP/4.3.4 mod_auth_pam_external/0.1 FrontPage/4.0.4.3 mod_perl/1.25
# Apache/1.3.20 Sun Cobalt (Unix) mod_jk mod_ssl/2.8.4 OpenSSL/0.9.6 PHP/4.0.6 FrontPage/5.0.2.2510 mod_auth_pam_external/0.1 mod_perl/1.26
# Apache/1.3.20 Sun Cobalt (Unix) mod_jk mod_ssl/2.8.4 OpenSSL/0.9.6 PHP/4.0.6 FrontPage/5.0.2.2510 mod_perl/1.26
# Apache/1.3.20 Sun Cobalt (Unix) mod_jk mod_ssl/2.8.4 OpenSSL/0.9.6 PHP/4.0.6 mod_auth_pam_external/0.1 FrontPage/5.0.2.2510 mod_perl/1.26
# Apache/1.3.20 Sun Cobalt (Unix) mod_jk mod_ssl/2.8.4 OpenSSL/0.9.6 PHP/4.1.2 mod_auth_pam_external/0.1 FrontPage/5.0.2.2510 mod_perl/1.26
# Apache/1.3.20 Sun Cobalt (Unix) mod_jk mod_ssl/2.8.4 OpenSSL/0.9.6 PHP/4.2.3 FrontPage/5.0.2.2510 mod_perl/1.26
# Apache/1.3.20 Sun Cobalt (Unix) mod_jk mod_ssl/2.8.4 OpenSSL/0.9.6 PHP/4.3.2 FrontPage/5.0.2.2510 mod_perl/1.26
# Apache/1.3.20 Sun Cobalt (Unix) mod_jk mod_ssl/2.8.4 OpenSSL/0.9.6 PHP/4.3.3 FrontPage/5.0.2.2510 mod_perl/1.26
# Apache/1.3.20 Sun Cobalt (Unix) mod_jk mod_ssl/2.8.4 OpenSSL/0.9.6 PHP/4.3.4 FrontPage/5.0.2.2510 mod_perl/1.26
# Apache/1.3.20 Sun Cobalt (Unix) mod_jk mod_ssl/2.8.4 OpenSSL/0.9.6 PHP/4.3.4 mod_auth_pam_external/0.1 FrontPage/5.0.2.2510 mod_perl/1.26
# Apache/1.3.20 Sun Cobalt (Unix) mod_jk mod_throttle/3.1.2 mod_ssl/2.8.4 OpenSSL/0.9.6 PHP/4.0.6 mod_auth_pam_external/0.1 FrontPage/5.0.2.2510 mod_perl/1.26
# Apache/1.3.20 Sun Cobalt (Unix) mod_ssl/2.8.4 OpenSSL/0.9.6b mod_auth_pam_external/0.1 FrontPage/4.0.4.3 mod_perl/1.25
# Apache/1.3.20 Sun Cobalt (Unix) mod_ssl/2.8.4 OpenSSL/0.9.6b (Webkun Logging) WEBKUN(tm)/1.1 PHP/4.0.6 mod_auth_pam_external/0.1 FrontPage/4.0.4.3 mod_perl/1.25
# Apache/1.3.20 Sun Cobalt (Unix) mod_ssl/2.8.4 OpenSSL/0.9.6g PHP/4.0.6 mod_auth_pam_external/0.1 FrontPage/4.0.4.3 mod_perl/1.25
# Apache/1.3.20 Sun Cobalt (Unix) mod_ssl/2.8.4 OpenSSL/0.9.6 PHP/4.0.6 FrontPage/5.0.2.2510 mod_auth_pam_external/0.1 mod_perl/1.26
# Apache/1.3.20 Sun Cobalt (Unix) mod_ssl/2.8.4 OpenSSL/0.9.6 PHP/4.0.6 FrontPage/5.0.2.2510 mod_perl/1.26
# Apache/1.3.20 Sun Cobalt (Unix) mod_ssl/2.8.4 OpenSSL/0.9.6 PHP/4.0.6 mod_auth_pam_external/0.1 FrontPage/5.0.2.2510 mod_perl/1.26
# Apache/1.3.20 Sun Cobalt (Unix) mod_ssl/2.8.4 OpenSSL/0.9.6 PHP/4.2.3 FrontPage/5.0.2.2510 mod_perl/1.26
# Apache/1.3.20 Sun Cobalt (Unix) mod_ssl/2.8.4 OpenSSL/0.9.6 PHP/4.3.3 mod_auth_pam_external/0.1 FrontPage/5.0.2.2510 mod_perl/1.26
# Apache/1.3.20 Sun Cobalt (Unix) mod_ssl/2.8.4 OpenSSL/0.9.6 PHP/4.3.4 FrontPage/5.0.2.2510 mod_perl/1.26
# Apache/1.3.20 Sun Cobalt (Unix) mod_throttle/3.1.2 mod_ssl/2.8.4 OpenSSL/0.9.6b PHP/4.0.6 mod_auth_pam_external/0.1 FrontPage/4.0.4.3 mod_perl/1.25
# Apache/1.3.20 Sun Cobalt (Unix) mod_throttle/3.1.2 mod_ssl/2.8.4 OpenSSL/0.9.6 PHP/4.0.6 mod_auth_pam_external/0.1 FrontPage/5.0.2.2510 mod_perl/1.26
# Apache/1.3.20 Sun Cobalt (Unix) mod_throttle/3.1.2 PHP/3.0.18-i18n-ja mod_ssl/2.8.4 OpenSSL/0.9.6b PHP/4.0.6 mod_auth_pam_external/0.1 FrontPage/4.0.4.3 mod_perl/1.25
# Apache/1.3.20 Sun Cobalt (Unix) PHP/4.0.6 mod_auth_pam_external/0.1 FrontPage/4.0.4.3 mod_perl/1.25
# Apache/1.3.20 Sun Cobalt (Unix) PHP/4.3.0 mod_ssl/2.8.4 OpenSSL/0.9.6b mod_auth_pam_external/0.1 FrontPage/4.0.4.3 mod_perl/1.25
# Apache/1.3.6 (Unix) mod_perl/1.21 mod_ssl/2.2.8 OpenSSL/0.9.2b
# Cobalt...
# Apache/1.3.20 Sun Cobalt
HTM:302:200:200:302:302:HTM:302:302:302:HTM:HTM:302:400:400:400:400:404:405:404:200:200:404:501:302:^Apache/1\.3\.(6|12|20) ((Sun )?Cobalt|\(Unix\)):Apache/1.3.6-20 [might Sun Cobalt]
# Apache/1.3.29 Sun Cobalt
# Apache/1.3.27 (Unix) PHP/4.1.2 mod_perl/1.27 mod_auth_pam/1.1.1 mod_ssl/2.8.12 OpenSSL/0.9.7
HTM:302:200:200:400:400:HTM:302:400:302:HTM:HTM:302:400:400:400:400:404:405:404:200:200:404:501:302:^Apache/1\.3\.2[7-9] (Sun Cobalt|\(Unix\)):Apache/1.3.27-29 (Unix)
HTM:302:200:200:400:400:HTM:302:400:302:HTM:HTM:302:400:400:400:400:404:403:403:200:200:404:501:302::Apache/1.3.29 Sun Cobalt (Unix) mod_ssl/2.8.16 OpenSSL/0.9.6m PHP/4.0.6 mod_auth_pam_external/0.1 mod_jk/1.1.0 FrontPage/4.0.4.3 mod_perl/1.25
# Apache/1.3.12 Cobalt (Unix) mod_ssl/2.6.4 OpenSSL/0.9.5a PHP/4.0.3pl1 mod_auth_pam/1.0a FrontPage/4.0.4.3 mod_perl/1.24
# Apache/1.3.20 Sun Cobalt (Unix) Chili!Soft-ASP/3.6.2 mod_ssl/2.8.4 OpenSSL/0.9.6b PHP/4.0.6 mod_auth_pam_external/0.1 FrontPage/4.0.4.3 mod_perl/1.25
# Apache/1.3.20 Sun Cobalt (Unix) Chili!Soft-ASP/3.6.2 mod_ssl/2.8.4 OpenSSL/0.9.6b PHP/4.1.2 mod_auth_pam_external/0.1 FrontPage/4.0.4.3 mod_perl/1.25
# Apache/1.3.20 Sun Cobalt (Unix) mod_jk mod_ssl/2.8.4 OpenSSL/0.9.6 PHP/4.0.6 FrontPage/5.0.2.2510 mod_perl/1.26
# Apache/1.3.20 Sun Cobalt (Unix) mod_ssl/2.8.4 OpenSSL/0.9.6 PHP/4.0.6 FrontPage/5.0.2.2510 mod_perl/1.26
# Apache/1.3.20 Sun Cobalt (Unix) mod_ssl/2.8.4 OpenSSL/0.9.6b mod_auth_pam_external/0.1 FrontPage/4.0.4.3 mod_perl/1.25
# Apache/1.3.20 Sun Cobalt (Unix) mod_ssl/2.8.4 OpenSSL/0.9.6b PHP/4.0.3pl1 mod_auth_pam_external/0.1 FrontPage/4.0.4.3 mod_perl/1.25
# Apache/1.3.20 Sun Cobalt (Unix) mod_ssl/2.8.4 OpenSSL/0.9.6b PHP/4.0.6 mod_auth_pam_external/0.1 FrontPage/4.0.4.3 mod_perl/1.25
# Apache/1.3.20 Sun Cobalt (Unix) mod_ssl/2.8.4 OpenSSL/0.9.6b PHP/4.0.6 mod_auth_pam_external/0.1 mod_jk/1.1.0 FrontPage/4.0.4.3 mod_perl/1.25
HTM:302:200:200:302:302:HTM:302:302:302:HTM:HTM:302:400:400:400:400:404:403:403:200:200:404:501:302::Apache/1.3.20 Sun Cobalt (Unix)
HTM:200:403:200:200:200:HTM:501:200:200:HTM:HTM:200:400:400:400:400:404:403:403:200:200:404:501:200::Apache/1.3.20 Sun Cobalt (Unix) PHP/4.0.6 mod_auth_pam_external/0.1 FrontPage/4.0.4.3 mod_ssl/2.8.4 OpenSSL/0.9.6b mod_perl/1.25
HTM:302:200:200:302:302:HTM:302:302:302:HTM:HTM:302:400:400:400:400:302:405:302:200:200:302:501:302::Apache/1.3.20 Sun Cobalt (Unix) mod_ssl/2.8.4 OpenSSL/0.9.6b PHP/4.1.2 mod_auth_pam_external/0.1 FrontPage/4.0.4.3 mod_perl/1.25
HTM:302:200:200:302:302:HTM:302:302:302:HTM:HTM:302:400:400:400:400:200:200:200:200:200:200:200:302::Apache/1.3.20 Sun Cobalt (Unix) mod_watch/3.14 mod_ssl/2.8.4 OpenSSL/0.9.6b PHP/4.0.6 mod_auth_pam_external/0.1 FrontPage/4.0.4.3 mod_perl/1.25
# http://www.geocities.com/SiliconValley/Platform/1297/misc/netchat.htm
404:200:501:200:200:200:404:501:200:404:404:404:200:200:200:404:200:501:501:501:501:501:501:501:500:^HTTPServer$:NetChat 7.4 on Windows 2000
# Nofeel FTP Server Standard Addition Version 3.2.3304.0 running on XP SP2
:400:200:400:505:505:505:400:200:505:400:400:400:---:400:400:400:400:+++:501:501:501:404:400:400:+++::NofeelSoft-WebFTP/1.0
# Nokia IP350 Checkpoint NG
HTM:200:200:200:200:200:HTM:200:200:200:HTM:HTM:200:400:400:400:400:200:405:404:200:200:404:501:200::Apache/1.3.6 (Unix) mod_auth_pam/1.0a mod_ssl/2.3.11 OpenSSL/0.9.5a 
# Apache/1.3.27 (Darwin) tomcat/1.0 mod_ssl/2.8.13 OpenSSL/0.9.6i
HTM:200:200:200:400:400:---:501:400:---:---:---:---:400:400:+++:400:404:405:404:200:200:404:501:+++::Apache/1.3.27 (Darwin)
HTM:200:200:200:400:400:---:501:400:---:---:---:---:400:400:+++:400:404:401:401:200:200:401:405:+++::Apache/1.3.27 (Darwin) DAV/1.0.3
HTM:200:200:200:400:400:HTM:501:400:200:HTM:HTM:200:400:400:+++:400:404:401:401:200:200:401:405:+++::Apache/1.3.27 (Darwin) DAV/1.0.3
HTM:200:200:200:400:400:---:200:400:---:---:---:---:400:400:400:400:404:405:404:200:403:404:501:---::Apache/1.3.29 (Darwin) PHP/4.3.2 DAV/1.0.3
HTM:200:403:200:400:400:HTM:501:400:200:HTM:HTM:200:400:400:400:400:404:403:403:200:200:404:501:200::Apache/1.3.27 (Unix) FrontPage/5.0.2.2510 mod_gzip/1.3.19.1a
# Apache/1.3.29 (Unix) mod_gzip/1.3.26.1a mod_ssl/2.8.16 OpenSSL/0.9.7c mod_jk/1.2.5
# Apache/1.3.28 (Darwin)
# IBM_HTTP_SERVER
# Apache/1.3.29 (Darwin) PHP/4.3.2
HTM:200:200:200:400:400:HTM:501:400:200:HTM:HTM:200:400:400:400:400:404:405:404:200:403:404:501:403:^Apache/1\.3\.2[89]:Apache/1.3.28-29 (Unix)
#### Apache Win32 ####
#  Apache through ACC reverse proxy
# Or IBM_HTTP_SERVER/1.3.28
HTM:200:400:HTM:200:HTM:400:HTM:HTM:200:400:400:200:400:400:400:200:404:400:400:200:200:501:501:200:Apache/1\.3\.28 \(Win32\):Apache/1.3.28 (Win32) through ACC reverse proxy or IBM_HTTP_SERVER/1.3.28
##HTM:200:200:200:200:200:HTM:501:200:200:HTM:HTM:200:200:400:+++:400:404:405:404:200:200:404:501:+++::Apache/1.3.24 (Win32) PHP/4.2.0
HTM:200:200:200:200:200:HTM:501:200:200:HTM:HTM:200:200:400:400:400:404:405:404:200:200:404:501:403::Apache/1.3.23 (Win32)
HTM:200:200:200:200:200:HTM:200:200:200:HTM:HTM:200:200:400:+++:400:404:405:404:200:200:404:501:+++::Apache/1.3.24 (Win32) PHP/4.2.0
HTM:200:200:200:200:200:HTM:200:200:200:HTM:HTM:200:200:400:400:400:404:405:404:200:200:404:501:403::IBM_HTTP_SERVER/1.3.20  Apache/1.3.20 (OS/2) PHP/4.1.1
HTM:200:200:200:400:400:HTM:400:400:200:HTM:HTM:200:200:400:400:400:403:403:403:403:200:403:403:403::Apache/1.3.26 (Win32) mod_perl/1.27
---:200:200:200:400:400:---:400:400:200:HTM:---:200:200:400:400:400:404:405:404:200:200:404:501:403::Apache/1.3.26 (Win32) mod_jk/1.1.0 mod_ssl/2.8.9 OpenSSL/0.9.6d
HTM:200:200:200:400:400:HTM:400:400:200:HTM:HTM:200:200:400:400:400:404:405:404:200:200:404:501:404::Apache/1.3.26 (Win32) mod_jk/1.2.0 mod_ssl/2.8.10 OpenSSL/0.9.7d
# Apache/1.3.29 (Win32) PHP/4.3.4  X-Powered-By: PHP/4.3.4 - Win 2000 SP3
# Apache/1.3.27 (Win32)
# Apache/1.3.27 (Win32) PHP/4.3.0
# Apache/1.3.27 (Win32) PHP/4.3.3RC1
# Apache/1.3.29 (Win32) PHP/4.3.6
HTM:200:200:200:400:400:HTM:200:400:200:HTM:HTM:200:200:400:400:400:404:405:404:200:200:404:501:403:^Apache/1\.3\.2[7-9] \(Win32\):Apache/1.3.27-29 (Win32) [w/ PHP4?]
xxx:200:200:200:200:200:xxx:200:200:200:xxx:xxx:200:200:400:+++:400:404:405:404:200:200:404:501:+++::Apache/1.3.24 (Win32) PHP/4.2.0
xxx:200:200:200:400:400:xxx:400:400:200:HTM:xxx:200:200:400:+++:400:404:405:404:200:200:404:501:+++::Apache/1.3.26 (Win32)
##HTM:200:200:200:400:400:HTM:400:400:200:HTM:HTM:200:200:400:+++:400:404:405:404:200:200:404:501:+++::Apache/1.3.26 (Win32) PHP/4.2.2
HTM:200:200:200:400:400:HTM:400:400:200:HTM:HTM:200:200:400:400:400:404:405:404:200:200:404:501:403::Apache/1.3.26 (Win32) mod_jk/1.1.0
# IBM_HTTP_SERVER/1.3.26.2 Apache/1.3.26 (Win32)
# Apache/1.3.29 (Win32)
HTM:200:200:200:400:400:HTM:200:400:200:HTM:HTM:200:200:400:400:400:200:200:200:200:200:200:200:200::^Apache/1\.3\.2[6-9] \(Win32\):Apache/1.3.26-29 (Win32)
---:200:403:200:200:200:---:501:200:200:HTM:---:200:200:400:400:400:404:405:404:200:200:404:501:403::IBM_HTTP_SERVER/1.3.19.3 Apache/1.3.20 (Win32)
HTM:404:403:200:404:404:HTM:501:404:404:HTM:HTM:404:404:400:400:400:200:200:200:200:200:200:200:403::IBM_HTTP_SERVER/1.3.19.3  Apache/1.3.20 (Win32)
HTM:301:501:200:400:400:400:400:400:---:HTM:---:301:301:400:400:400:404:405:405:501:501:501:501:301::IBM_HTTP_SERVER/1.3.26.2  Apache/1.3.26 (Win32)
# Operating system : Windows NT4.0 SP 6.a
HTM:200:200:200:400:400:HTM:501:400:200:HTM:HTM:200:200:400:400:400:404:405:404:200:403:404:501:403::Apache/1.3.29 (Win32) ApacheJServ/1.1.2 mod_ssl/2.8.16 OpenSSL/0.9.6m
# Apache/1.3.17 (Win32)
# Apache/2.0.48 (Win32) PHP/4.3.5RC2-dev
# IBM_HTTP_SERVER/1.3.19.6 Apache/1.3.20 (Win32)
HTM:200:403:200:200:200:HTM:200:200:200:HTM:HTM:200:200:400:400:400:200:200:200:200:200:200:200:200:Apache/[12]\.[30]\.([14][789]|20) \(Win32\):Apache/1.3.17-20 or 2.0.48 (Win32)
# Apache/2.0.39 (Win32) w/ PHP/4.1.2
##HTM:200:200:200:200:200:HTM:200:200:200:HTM:HTM:200:200:400:+++:400:404:405:405:200:200:405:501:+++::Apache/2.0.39 (Win32)
# More specific signature
HTM:200:200:200:200:200:HTM:200:200:200:HTM:HTM:200:200:400:400:400:404:405:405:200:200:405:501:200::Apache/2.0.43 (Win32) JRun/4.0
# Apache/2.0.45 (Win32)
# Apache/2.0.47 (Win32) mod_python/3.0.3 Python/2.2.3
# Apache/2.0.47 (Win32) PHP/4.3.3
# Apache/2.0.48 (Win32)
##HTM:200:403:200:200:200:HTM:501:200:200:HTM:HTM:200:200:400:+++:400:404:405:405:200:200:405:501:+++:^Apache/2\.0\.4[5-8] \(Win32\):Apache/2.0.45-48 (Win32)
# Apache/2.0.48 (Win32)
# Apache/2.0.48 (Win32) PHP/4.3.4
# Apache/2.0.49 (Win32)
# Apache/2.0.47 (Win32)
# Apache/2.0.54 (Win32)
# Apache/2.2.3 (Win32)
HTM:200:403:200:200:200:HTM:501:200:200:HTM:HTM:200:200:400:400:400:404:405:405:200:200:405:501:200:^Apache/2\.(0\.(4[7-9]|5[0-4])|2\.[0-3]) \(Win32\):Apache/2.0.47-2.2.3 (Win32)
# Apache/2.0.40 (Win32)
# Apache/2.0.35 (Win32)
##HTM:200:200:200:200:200:HTM:501:200:200:HTM:HTM:200:200:400:+++:400:404:405:405:200:200:405:501:+++:^Apache/2\.0\.[34][05].*Win32:Apache/2.0.35-40 (Win32)
# More precise
# Apache/2.0.39 (Win32) mod_ssl/2.0.39 OpenSSL/0.9.6d
# Apache/2.0.39 (Win32) PHP/4.2.2
# Apache/2.0.35 (Win32)
HTM:200:200:200:200:200:HTM:501:200:200:HTM:HTM:200:200:400:400:400:404:405:405:200:200:405:501:403:^Apache/2\.0\.3[5-9].*Win32:Apache/2.0.35-39 (Win32)
# Apache/2.0.40 (Win32)
# Apache/2.0.43 (Win32)
HTM:200:200:200:200:200:HTM:501:200:200:HTM:HTM:200:200:400:400:400:404:405:405:200:200:405:501:200:^Apache/2\.0\.4[0-3] \(Win32\):Apache/2.0.40-43 (Win32)
# The httpd.conf differs from redhat distribution by rewrite stuff to 
# disable TRACE/TRACK and by .htaccess being enabled. No virtual 
# domains. 
HTM:200:200:200:200:200:HTM:501:200:200:XML:HTM:200:400:400:400:400:404:405:405:200:403:405:405:200::Apache/2.0.40 (Red Hat Linux) [w/ PHP/4.2.2 and mod_dav]
# Apache/2.0.47 (Win32) PHP/4.3.2
# Apache/2.0.47 (Win32) mod_python/3.0.3 Python/2.2.3
##HTM:200:403:200:200:200:HTM:200:200:200:HTM:HTM:200:200:400:+++:400:404:405:405:200:200:405:501:+++::Apache/2.0.47 (Win32)
# Apache/2.0.47 (Win32) PHP/4.3.4
# Apache/2.0.44 (Win32)
# Apache/2.0.48 (Win32) PHP/4.3.5
# Apache/2.0.49 (Win32) PHP/4.3.5
# Apache/2.0.54 (Win32) mod_ssl/2.0.53 OpenSSL/0.9.7e PHP/5.0.2
HTM:200:403:200:200:200:HTM:200:200:200:HTM:HTM:200:200:400:400:400:404:405:405:200:200:405:501:200:^Apache/2\.0\.(4[4-9]|5[04]) \(Win32\):Apache/2.0.44-54 (Win32)
# Apache/2.0.44 (Win32) PHP/4.3.1
# Apache/2.0.44 (Win32) PHP/4.3.1-dev
# Apache/2.0.48 (Win32)
HTM:200:403:200:200:200:HTM:501:200:200:XML:HTM:200:200:400:400:400:404:405:405:200:200:405:501:200:^Apache/2\.0\.4[-9]8 \(Win32\):Apache/2.0.44-48 (Win32)
HTM:200:403:200:200:200:HTM:403:200:200:XML:HTM:200:200:400:400:400:404:403:403:403:403:403:403:200::Apache/2.0.46 (Win32) mod_ssl/2.0.45 OpenSSL/0.9.7b
HTM:200:403:503:503:503:HTM:500:503:200:HTM:HTM:200:200:400:400:400:404:405:405:200:200:405:501:200::Apache/2.0.48 (Win32) mod_jk2/2.0.4-dev
# Apache 2.0.55.0 PHP 5.1.2.2 on Windows 2000 Professional Build 2195
HTM:200:403:200:200:200:HTM:200:200:200:HTM:HTM:200:200:400:400:400:302:302:302:302:302:302:302:200::Apache/2.0.55.0 (Win32) [w/ PHP/5.1.2.2]
# Uniform Server v3.3 on Windows XP Pro SP2
HTM:200:403:200:200:200:HTM:501:200:200:HTM:HTM:200:200:400:400:400:404:201:404:200:200:404:405:200::Apache/2.0.55 (Win32) DAV/2 PHP/5.1.1
# Oracle HTTP Server Powered by Apache/1.3.12 (Win32) ApacheJServ/1.1 mod_ssl/2.6.4 OpenSSL/0.9.5a mod_perl/1.24
# Apache/1.3.12 (Win32) ApacheJServ/1.1 mod_ssl/2.6.4 OpenSSL/0.9.5a mod_perl/1.22
# Apache/1.3.17 (Win32)
##HTM:200:403:200:200:200:HTM:501:200:200:HTM:HTM:200:200:400:+++:400:404:405:404:200:200:404:501:+++:Apache/1\.3\.1[27] (Win32):Apache/1.3.12-17 (Win32)
# More precise
HTM:200:403:200:200:200:HTM:501:200:200:HTM:HTM:200:200:400:400:400:404:405:404:200:200:404:501:+++::Oracle HTTP Server Powered by Apache/1.3.22 (Win32) mod_plsql/3.0.9.8.3b mod_ssl/2.8.5 OpenSSL/0.9.6b mod_fastcgi/2.2.12 mod_oprocmgr/1.0 mod_perl/1.25
# Even more precise!
# IBM_HTTP_Server/1.3.12.3 Apache/1.3.12 (Win32)
# IBM_HTTP_SERVER/1.3.19.3 Apache/1.3.20 (Win32)
# IBM_HTTP_SERVER/1.3.19.3  Apache/1.3.20 (Win32)
# TBD: control the 3 next signatures
# IBM_HTTP_Server/1.3.12.2 Apache/1.3.12
# IBM_HTTP_SERVER/1.3.19  Apache/1.3.20 (Win32)
# IBM_HTTP_Server/1.3.6.2 Apache/1.3.7-dev (Win32)
# Apache/1.3.12 (Win32)
# Apache/1.3.17 (Win32)
# Apache/1.3.20 (Win32)
# Apache/1.3.22 (Win32)
# Oracle HTTP Server Powered by Apache/1.3.19 (Win32) PHP/4.2.1 mod_ssl/2.8.1 OpenSSL/0.9.5a mod_fastcgi/2.2.10 mod_oprocmgr/1.0 mod_perl/1.25
# Oracle HTTP Server Powered by Apache/1.3.22 (Win32) mod_plsql/3.0.9.8.3b mod_ssl/2.8.5 OpenSSL/0.9.6b mod_fastcgi/2.2.12 mod_oprocmgr/1.0 mod_perl/1.25
# Oracle HTTP Server Powered by Apache/1.3.22 (Win32) mod_plsql/3.0.9.8.3b mod_ssl/2.8.5 OpenSSL/0.9.6b mod_fastcgi/2.2.12 mod_oprocmgr/1.0 mod_perl/1.25
# Oracle9iAS/9.0.2.3.0 Oracle HTTP Server
HTM:200:403:200:200:200:HTM:501:200:200:HTM:HTM:200:200:400:400:400:404:405:404:200:200:404:501:403:(Apache/1\.3.(1[2-9]|2[0-2]) \(Win32\)|^Oracle9iAS/9.0.2.3.0 Oracle HTTP Server$):Apache/1.3.12-22 (Win32) [may be IBM_HTTP_SERVER or Oracle HTTP Server]
HTM:200:403:200:200:200:HTM:200:200:200:HTM:HTM:200:200:400:400:400:404:405:404:200:200:404:501:403::Apache/1.3.22 (Win32)
# Apache/1.3.27 (Win32)
# Apache/1.3.28 (Win32)
# Apache/1.3.28 (Win32) PHP/4.3.2
# Apache/1.3.28 (Win32) PHP/4.3.3
##HTM:200:200:200:400:400:HTM:501:400:200:HTM:HTM:200:200:400:+++:400:404:405:404:200:200:404:501:+++:^Apache/1\.3\.2[78]:Apache/1.3.27-28 (Win32)
# Same as above but more precise
# IBM_HTTP_SERVER/1.3.26.2  Apache/1.3.26 (Win32)
# IBM_HTTP_SERVER/1.3.26  Apache/1.3.26 (Win32)
# Apache/1.3.27 (Win32)
# Apache/1.3.27 (Win32) PHP/4.3.0
# Apache/1.3.28 (Win32)
# Apache/1.3.28 (Win32) PHP/4.2.1
# Apache/1.3.28 (Win32) PHP/4.3.2
# OpenSA/1.0.4 / Apache/1.3.27 (Win32) PHP/4.2.2 mod_gzip/1.3.19.1a DAV/1.0.3
# Oracle-Application-Server-10g/10.1.2.0.2
HTM:200:200:200:400:400:HTM:501:400:200:HTM:HTM:200:200:400:400:400:404:405:404:200:200:404:501:403:^((Oracle-Application-Server-10g/10)|(Apache/(1\.3\.2[6-9] \(Win32\))?)):Apache/1.3.26-29 (Win32) [may be IBM_HTTP_SERVER/1.3.2x or OpenSA/1.0.x] or Oracle-Application-Server-10g/10.1.2.0.2
# Novell 6 server running Apache Tomcat 3.2.2 and 3.3 with Novell JVM 1.3.0_02.
HTM:200:403:200:400:400:HTM:501:400:200:HTM:HTM:200:400:400:400:400:404:405:404:200:200:404:501:+++::Apache/1.3.27 (NETWARE) mod_jk/1.2.2-dev
# Same as above but more precise
# Apache/1.3.27-29 (NETWARE) mod_jk/1.2.2-dev
# Apache/1.3.28 (Unix) mod_ssl/2.8.15 OpenSSL/0.9.7c
HTM:200:403:200:400:400:HTM:501:400:200:HTM:HTM:200:400:400:400:400:404:405:404:200:200:404:501:403:^Apache/1\.3\.2[789] \(NETWARE|Unix\):Apache/1.3.27-29 (Netware/Unix)
# Also more precise
# Apache/1.3.29 (Unix) mod_ssl/2.8.16 OpenSSL/0.9.7c PHP/4.3.3
# Apache/1.3.33 (Unix) OpenSSL/0.9.6m PHP/4.3.11
HTM:200:403:200:400:400:HTM:501:400:200:HTM:HTM:200:400:400:400:400:404:405:404:200:200:404:501:200:^Apache/1\.3\.(2[789]|3[0-3]) \(Unix\):Apache/1.3.27-33 (Unix) [w/ PHP 4.3]
################
# A secure web server that crashes when it receives 'GET\r\n\r\n' :)
200:200:301:200:200:200:---:301:200:301:301:---:200:404:404:404:200:404:301:301:301:301:301:301:200:^Anti-Web V3\.0\.2:Anti-Web V3.0.2
200:200:301:200:200:200:404:301:200:301:301:404:200:404:404:404:200:404:301:301:301:301:301:301:200:^Anti-Web V3\.0\.3:Anti-Web V3.0.3 [fixed by MA]
---:200:---:200:200:200:---:---:200:---:---:---:---:200:200:200:200:---:---:---:---:---:---:---:200::Azureus 2.2.0.2
HTM:200:501:200:200:200:HTM:501:200:200:HTM:HTM:200:400:400:400:200:501:501:501:501:501:501:501:200::awkhttp.awk/-1.99.8
# What is BATM?
200:200:---:200:200:200:404:200:200:200:---:404:200:404:404:+++:200:---:---:---:---:---:---:---:+++::BATM
# HP OpenView Embedded BBC Web Server
---:404:404:505:505:505:---:404:505:505:505:505:404:---:404:404:404:+++:404:404:404:404:404:404:+++:^BBC:HP OpenView BBC Web Server
# belkin Wireless broadband router (4 Port); Firmware Version:V1.10.008; Boot Version:V1.13; Hardware :01
400:200:400:200:200:200:400:400:200:400:400:400:---:404:404:404:200:404:400:400:400:400:400:400:400:^$:Belkin wireless broadband router
# See http://www.myipis.com/
404:200:404:200:200:200:404:200:200:404:404:404:---:404:404:404:200:404:404:404:404:404:404:404:404::BlackcombHTTP Server (beta 0.4)
# bozohttpd/20031005 on FreeBSD 5.2.1, thru inetd
# bozohttpd/20040823 on Gentoo, thru inetd
200:200:404:404:200:404:404:200:404:200:404:404:200:404:404:404:400:400:404:404:404:404:404:404:403::bozohttpd
200:200:---:200:200:200:---:---:200:200:---:---:200:200:200:404:200:---:---:---:---:---:---:---:404::bttrack.py/3.4.2 [BitTorrent tracker]
# MA: I suspect that Bull-SMW is based upon CERN httpd
HTM:200:400:200:200:200:HTM:400:HTM:200:HTM:HTM:200:200:200:403:200:+++:403:403:400:400:400:400:+++::Bull-SMW/1.1
404:200:404:200:200:200:404:404:200:404:404:404:200:404:404:404:200:200:404:404:404:404:404:404:+++::CERN/3.0 [Edimax Broadband router type BR-6004]
HTM:200:400:200:200:200:HTM:400:HTM:200:HTM:HTM:200:403:403:+++:200:500:403:403:400:400:400:400:+++::CERN/3.0
HTM:200:400:200:200:200:HTM:400:HTM:200:HTM:HTM:200:403:403:+++:200:200:403:403:400:400:400:400:+++::CERN/3.0
HTM:200:400:200:200:200:HTM:400:HTM:200:HTM:HTM:200:403:403:+++:200:403:403:403:400:400:400:400:+++::CERN/3.0pre6vms3
# Boa 0.94.12 or 0.94.13
HTM:200:501:HTM:HTM:HTM:501:501:HTM:501:501:501:200:400:400:+++:200:400:501:501:501:501:501:501:200:Boa/0\.94\.1[23]:Boa/0.94
HTM:200:400:200:200:HTM:400:HTM:HTM:200:400:400:200:404:404:+++:200:404:400:400:400:400:400:400:+++::Boa/0.92o
#
200:200:200:200:400:400:400:400:400:400:400:400:200:404:404:+++:400:404:501:501:200:200:400:400:+++::Canon Http Server 1.00
200:200:200:200:200:200:400:200:200:400:400:400:200:200:200:+++:+++:200:200:200:200:200:200:200:+++::Cassini/1.0.1403.33443
# Caudium/1.3.5 + X-Got-Fish: Pike v7.3 release 58
500:200:501:200:200:200:xxx:501:200:500:500:xxx:---:404:302:+++:200:404:405:405:501:501:405:501:+++::Caudium/1.3.5 DEVEL (Debian GNU/Linux)
# Caudium/1.2.35 + X-Got-Fish: Pike v7.2 release 580
500:200:501:200:200:200:xxx:501:200:500:500:xxx:---:404:302:302:200:404:405:405:501:501:501:501:200::Caudium/1.2.35 STABLE
500:401:401:401:401:401:xxx:401:401:500:500:xxx:---:401:401:401:401:401:401:401:401:401:401:401:401::Caudium/1.2.35 STABLE [administration interface]
#
xxx:200:xxx:xxx:xxx:xxx:xxx:xxx:404:xxx:xxx:xxx:---:400:400:400:200:404:xxx:xxx:xxx:xxx:xxx:xxx:404::Cherokee/0.4.2
---:200:400:400:400:---:---:400:400:400:---:400:---:400:400:400:400:411:405:405:405:405:405:411:200::Cherokee/0.4.30 (Gentoo Linux)
# Cherokee/0.5.0 (Gentoo Linux) [basic configuration]
# Cherokee/0.5.1 (Gentoo Linux)
# Cherokee/0.5.2 (Gentoo Linux)
# Cherokee/0.5.5 (Gentoo Linux)
---:200:400:400:400:---:---:400:400:400:---:400:---:400:400:400:400:411:404:404:404:404:404:411:200:^Cherokee/0\.5\.[0-5] :Cherokee/0.5.0 to 0.5.5
400:200:400:200:200:200:400:400:200:400:400:400:200:200:200:200:200:404:400:400:400:400:400:400:---:^$:Cisco Access Point AP4800E v8.80
---:---:405:505:400:400:400:200:---:---:400:400:200:400:400:400:400:+++:501:501:404:404:404:404:+++::cisco-IOS [12.3]
xxx:200:405:505:400:400:400:200:400:200:400:400:200:400:400:400:400:411:501:501:404:404:404:404:+++::cisco-IOS
400:200:501:200:200:400:---:200:400:200:---:---:200:200:200:501:200:200:501:501:501:501:501:501:+++:^$:cisco-IOS 11.2
---:200:501:200:200:400:---:200:400:200:---:---:200:200:200:501:200:200:501:501:501:501:501:501:200:^$:cisco-IOS 11.2
---:200:501:200:200:400:400:200:400:200:400:400:200:200:200:501:200:200:501:501:501:501:501:501:200:^$:cisco-IOS 12.0(3)T, fc1 on a Cisco 1603
---:200:501:200:200:400:---:200:400:200:---:---:200:200:200:501:200:---:501:501:501:501:501:501:+++:^$:cisco-IOS/12.1 HTTP-server/1.0(1)
# Cisco Internetwork Operating System Software IOS (tm) C2900XL Software (C2900XL-C3H2S-M), Version 12.0(5.2)XU, MAINTENANCE INTERIM SOFTWARE
---:200:501:200:200:400:---:200:400:200:---:---:200:200:---:501:200:200:501:501:501:501:501:---:+++:^$:cisco-IOS 12.0(5.2)XU
---:---:---:---:---:400:---:200:---:---:---:---:---:---:---:---:---:---:---:---:---:---:---:---:---:^$:IOS Version 12.0(12), RELEASE SOFTWARE (fc1), running on a Cisco 1600
200:200:---:200:200:200:---:---:200:---:---:---:200:200:200:---:200:200:---:---:---:---:---:---:+++:^$:DSL modem Cisco 678 running CBOS
200:200:500:200:200:200:200:500:200:500:500:200:200:500:500:500:200:500:500:500:500:500:500:500:+++:^$:Cisco Secure ACS v3.0.x on Windows 2000
400:302:---:505:505:505:400:302:505:400:400:400:302:404:404:404:400:404:403:404:404:404:501:501:---::CL-HTTP/70.182 (Symbolics Common Lisp)
400:200:400:200:200:400:400:200:200:400:400:400:---:400:400:400:200:404:400:400:400:400:400:400:404::Code Ocean Ocean Mail Server 1.06
# CUPS
200:200:200:505:400:400:400:400:400:200:400:400:200:405:405:+++:200:401:403:---:200:---:400:400:+++::CUPS/1.1
200:200:200:505:400:400:400:400:400:200:400:400:200:405:405:+++:200:404:403:---:200:---:400:400:+++::CUPS/1.1
403:403:200:505:400:400:400:400:400:403:400:400:403:405:405:405:403:403:403:403:200:403:400:400:400::CUPS/1.1 [forbidden access]
# Compaq Web Management (?)
---:200:---:---:200:---:---:---:---:---:---:---:200:200:404:405:200:404:405:---:---:---:---:---:+++::CompaqHTTPServer/1.0
---:200:---:---:200:---:---:---:---:---:---:---:200:404:200:405:200:404:405:---:---:---:---:---:+++::CompaqHTTPServer/1.0 [Windows 2000]
---:200:510:---:200:---:---:---:---:---:---:---:200:404:200:405:200:404:405:---:510:---:---:---:+++::CompaqHTTPServer/2.1 [Windows NT]
---:404:510:---:404:---:---:---:---:---:---:---:404:200:404:405:404:+++:405:---:510:---:---:---:+++:^CompaqHTTPServer/5\.[7-9]:CompaqHTTPServer/5.7 to 5.94
# More precise
---:404:510:---:404:---:---:---:---:---:---:---:404:200:404:405:404:404:405:---:510:---:---:---:+++:^CompaqHTTPServer/5\.[7-9]:CompaqHTTPServer/5.7 to 5.9
# Compaq Insight (std install) on Windows 2000
---:404:510:---:404:---:---:---:---:---:---:---:404:404:404:405:404:404:405:---:510:---:---:---:+++:^CompaqHTTPServer/[45]\.[012]:Compaq Insight 4.1 or 5.2 on Windows 2000
#
---:200:510:---:200:---:---:---:---:---:---:---:200:200:200:+++:+++:200:405:---:510:---:---:---:+++::CompaqHTTPServer/5.0
# More precise
---:200:510:---:200:---:---:---:---:---:---:---:200:200:200:405:200:+++:405:---:510:---:---:---:+++:^CompaqHTTPServer/5\.[7-9]:CompaqHTTPServer/5.7 to 5.91
---:200:510:---:200:---:---:---:---:---:---:---:200:200:200:405:200:200:405:---:510:---:---:---:+++::CompaqHTTPServer/5.91
# Even more precise (but also 2.1??)
---:200:510:---:200:---:---:---:---:---:---:---:200:200:200:405:200:200:405:---:510:---:---:---:413::CompaqHTTPServer/[2-5]\.:CompaqHTTPServer/2.1 to 5.94
---:200:510:---:200:---:---:---:---:---:---:---:200:200:200:405:200:200:405:---:510:---:---:---:200::CompaqHTTPServer/5.7
#
---:200:510:---:200:---:---:---:---:---:---:---:200:200:200:405:200:404:405:---:510:---:---:---:+++::CompaqHTTPServer/2.1
# Runs on Mac OSX Panther
---:200:200:503:200:---:---:200:---:---:---:---:200:---:---:---:200:404:404:404:200:---:---:---:+++::CommuniGatePro/4.1.8
---:200:200:---:200:---:---:200:---:---:---:---:200:---:---:---:200:404:404:404:200:---:---:---:404::CommuniGatePro/4.3.6
# Is Communique built upon Apache?
xxx:200:200:200:400:400:xxx:501:400:200:HTM:xxx:200:400:400:+++:400:404:405:404:200:403:404:501:+++::Communique/2.5.0 (build 4850)
# David-WebBox/6.60a (0297)
# David-WebBox/7.00a (0312)
# David-WebBox/7.00a (0314)
---:200:---:200:200:200:---:200:---:200:---:---:---:302:404:200:200:302:302:302:---:---:---:---:302::David-WebBox
# IBM Desktop On Call 4.0 (?) on eComStation 1.1 (aka OS/2)
HTM:200:---:200:200:200:404:200:200:404:404:404:---:200:404:+++:200:---:---:---:---:---:---:---:+++::Desktop On-Call HTTPD V3.0
# Novell eDirectory 8.7.3 HTTP server  (admin stuff)
HTM:200:501:200:200:---:HTM:---:200:---:---:HTM:200:404:404:404:400:404:501:501:501:501:---:---:500::DHost/9.0 HttpStk/1.0
# Hardware:DSL-300G
# OS:D-Link Corp., Software Release R2.01M.B2.TA(021206a/T93.3.23)
200:200:501:200:200:200:200:501:200:200:200:200:---:200:200:200:200:200:501:501:501:501:501:501:+++:^$:D-Link ADSL router [DSL-300G Software Release R2.01M.B2.TA(021206a/T93.3.23)]
# Model: Vigor2600 annex A 
# Firmware Version : v2.5_UK 
# Build Date/Time : Fri Aug 29 21:0:23.61 2003 
HTM:200:400:200:200:200:HTM:400:200:HTM:HTM:HTM:200:400:400:302:200:501:400:400:400:400:400:400:+++:^$:Draytek 2200 ADSL Vigor Router
#
HTM:200:400:HTM:HTM:HTM:HTM:HTM:HTM:200:HTM:HTM:200:400:400:+++:200:500:405:405:405:405:501:501:+++::DECORUM/2.0
HTM:200:405:HTM:HTM:HTM:HTM:HTM:HTM:200:HTM:HTM:200:200:404:+++:200:405:405:405:405:405:501:501:+++::DECORUM/2.0
200:200:550:200:200:200:---:200:200:---:---:---:---:---:550:---:200:550:550:550:550:550:550:550:---::DManager [Surgemail 30c2 (windows XP)]
505:200:400:505:505:505:505:505:505:200:505:505:---:404:404:404:200:400:400:400:400:400:400:400:200::DNHTTPD/0.6
# Web server (upsis.exe from OPTI-SAFE Xtreme) for monitoring & configuration of OPTI-UPS VS375C -- client version v3.2b
400:200:501:501:400:501:400:400:400:400:400:400:400:200:404:404:400:+++:200:200:501:501:200:501:+++::dnpower [OPTI-SAFE Xtreme for OPTI-UPS]
505:200:400:505:505:505:505:505:505:200:505:505:---:404:404:403:200:400:400:400:400:400:400:400:200::Ranquel-0.1.2
# On FreeBSD 5.2.1
200:200:400:200:200:200:403:400:200:200:400:403:200:404:403:400:200:400:400:400:400:400:400:400:403::dhttpd/1.02a
# This is the AnswerBook.
200:200:---:200:200:200:200:200:200:200:200:200:---:200:200:404:200:---:---:---:---:---:---:---:---::dwhttpd/4.2a7 (Inso; sun5)
200:200:---:200:200:200:200:---:200:200:200:200:---:200:200:+++:200:---:---:---:---:---:---:---:+++::ELOG HTTP 2.3.6
200:200:403:200:200:200:403:403:200:403:403:403:200:200:403:403:200:200:200:200:200:200:200:200:200::Embedded HTTPD v1.00, 1999(c) Delta Networks Inc.
# Embedded HTTP Server 2.05b3 [FIREBOX SOHO 6tc]
# Embedded HTTP Server 1.01 [D-Link DI-624+ Current Firmware Version: 1.01]
xxx:200:501:VER:VER:VER:400:VER:xxx:200:400:400:200:400:400:400:200:404:501:501:501:501:501:501:+++::Embedded HTTP Server
#
---:200:200:200:200:200:---:200:200:---:---:---:200:200:200:200:200:200:200:200:200:200:200:200:---::Apache/0.6.5 [Edimax broadband router, model 6104, version 0.59WD (Nov 07 2002 09:52:40)]
# emac-httpd thru xined :-)
200:200:400:200:200:200:400:200:200:200:400:400:---:400:400:403:200:503:400:400:400:400:400:400:301::Emacs/httpd.el
200:200:501:VER:VER:VER:302:200:HTM:501:501:302:200:302:302:403:200:200:501:501:501:501:501:501:403::Fastream NETFile Web Server 7
HTM:200:400:200:200:200:HTM:200:200:HTM:HTM:HTM:200:404:302:302:200:404:503:400:400:400:400:400:200::fhttpd
##200:200:404:200:200:200:---:200:200:---:---:---:---:404:404:+++:200:---:---:404:404:404:404:404:+++::FileMakerPro/4.0
# FMP 5.0 MacOS 8.6 - same as above, more precise
200:200:404:200:200:200:---:200:200:---:---:---:---:404:404:404:200:---:---:404:404:404:404:404:+++::FileMakerPro/5.0
# WatchGuard SOHO (FTP Server version 2.4.19) internet security appliance
200:200:401:200:200:200:---:404:200:---:---:---:---:401:401:401:200:401:401:401:401:401:401:401:+++::Firewall [SOS internet appliance]
# typical for CheckPoint Firewall-1 NG FP3 or NG AI versions
200:200:---:200:200:200:---:200:200:---:---:---:---:200:200:---:200:---:---:---:---:---:---:---:+++:^$:Checkpoint FW-1 NG HTTP authentication proxy
400:200:400:400:200:400:400:400:400:400:400:400:200:400:400:400:200:404:400:400:400:400:400:400:200:^fnord/1\.([89]|10):fnord/1.8-1.10
400:404:400:400:404:400:400:400:400:400:400:400:404:400:400:400:404:404:400:400:400:400:400:400:404::fnord/1.8 [unconfigured]
HTM:200:200:200:200:200:HTM:400:200:200:HTM:HTM:200:400:400:400:400:400:400:400:200:400:400:400:200:^$:Fortigate firewall web management
200:200:405:200:200:200:405:405:200:405:405:405:200:404:404:404:200:400:405:405:405:405:405:405:400::Foundry Networks/2.20
# Fred 0.5 (build 5076) HTTP Servlets
# Fred 0.5 (build 5105) HTTP Servlets
400:302:200:302:400:400:400:302:400:400:400:400:302:302:302:302:302:---:404:404:404:404:404:404:404:^Fred 0\.5 \(build 5[0-9]{3}\) HTTP Servlets$:Fred 0.5 (build 5xxx) HTTP Servlets [Freenet]
404:200:404:200:200:200:404:200:200:404:404:404:200:200:404:404:200:404:404:404:404:404:404:404:404:^$:FTGate
# Gordano (installed by Messaging Suite)
200:200:---:200:200:200:200:200:200:200:200:200:200:---:---:+++:+++:200:200:200:200:200:200:200:+++::Gordano Web Server v5.06.0016
200:200:400:200:200:200:501:200:200:501:501:501:200:400:400:+++:+++:302:501:501:501:501:501:501:+++::Gordano Messaging Suite Web Server v9.01.3158
---:302:---:---:---:---:---:302:---:---:---:---:302:200:200:200:302:411:---:---:HTM:---:---:---:200::GWS/2.1
# HP JetDirect 600N (J3110A)
# Version: ROM G.08.08, EPROM G.08.20
HTM:200:404:xxx:xxx:xxx:xxx:xxx:xxx:xxx:xxx:xxx:xxx:404:404:404:200:404:404:404:404:404:404:404:+++:HTTP/1\.0:HP JetDirect 600N (J3110A)
xxx:200:200:200:200:200:xxx:501:200:200:HTM:xxx:200:200:400:+++:400:404:405:405:200:200:405:501:+++::HP Web Jetadmin/2.0.39 (Win32) mod_ssl/2.0.39 OpenSSL/0.9.6c
# HP JetDirect 600N (J3113A) with latest firmware (G.08.49)
# Probably the same signature as above; the HTML identification code changed recently
HTM:200:404:HTM:HTM:HTM:xxx:HTM:HTM:xxx:xxx:xxx:xxx:404:404:404:200:404:404:404:404:404:404:404:+++:HTTP/1\.0:HP JetDirect 600N (J3113A) with G.08.49 firmware
# Two signatures from HP RX 2600
HTM:200:501:200:HTM:HTM:HTM:HTM:HTM:200:HTM:HTM:200:404:404:+++:200:501:501:501:501:501:501:501:+++:^$:HP Web Console [HP RX 2600]
HTM:200:501:200:HTM:---:---:---:---:---:---:---:---:---:---:+++:---:---:---:---:---:---:---:---:+++:^$:HP Web Console [HP RX 2600]
200:200:405:200:200:200:200:405:200:405:405:200:200:200:200:200:200:+++:404:405:405:405:405:405:+++:^$:MarkNet / HP Laserjet printer
#
---:200:---:---:---:---:---:---:---:---:---:---:---:404:404:404:200:404:404:---:---:---:---:---:404:^eHTTP v1\.0:HP ProCurve Switch 2524 J4813A release #F.05.17
505:200:---:505:200:505:505:---:505:---:---:200:---:404:---:404:200:---:---:---:---:---:---:---:+++:^EHTTP/1\.1:HP J4121A ProCurve Switch 4000M Firmware revision C.09.19
HTM:200:HTM:200:200:HTM:HTM:HTM:HTM:200:HTM:200:200:200:200:200:200:200:200:200:HTM:HTM:HTM:HTM:200::Motive Chorus (HP Instant Support Enterprise Edition)
#
200:200:400:200:200:200:400:400:200:200:400:400:200:200:200:200:200:200:400:400:400:400:400:400:200:^$:HTTP::Server::Simple [unconfigured Perl module] 
#
200:200:501:200:200:200:---:501:200:200:---:---:200:200:200:200:200:404:500:501:501:501:501:501:404::Hyperwave-Information-Server/5.5
200:200:200:200:200:200:---:501:200:200:---:---:200:200:200:200:200:404:401:404:200:500:400:500:404::Hyperwave-Information-Server/5.5
200:200:501:200:200:200:---:501:200:200:---:---:200:200:200:200:200:404:400:501:501:501:501:501:200::Hyperwave-IS/6
# A Polish server, it seems. Can anybody provide details?
HTM:200:---:200:200:200:---:400:200:200:---:---:200:---:---:---:400:404:400:400:400:400:400:400:200::IdeaWebServer/v0.21
XML:200:---:200:200:200:---:400:200:200:---:---:200:---:---:---:400:404:400:400:400:400:400:400:200::IdeaWebServer/v0.21
HTM:200:---:200:200:200:---:400:200:200:---:---:200:---:---:---:400:302:400:400:400:400:400:400:200::IdeaWebServer/v0.21
---:200:---:200:200:200:---:400:200:200:---:---:200:---:---:---:400:404:400:400:400:400:400:400:200::IdeaWebServer/v0.21
#
HTM:200:404:VER:VER:VER:HTM:VER:HTM:200:HTM:HTM:200:200:200:404:400:+++:404:404:404:404:404:404:+++::IMV Web Server v1.0
200:200:---:200:200:200:---:200:200:---:---:---:200:200:200:404:200:---:---:---:---:---:---:---:404::Indy/8.0.25 [www.minihttpserver.net]
404:200:---:200:200:200:---:200:200:---:---:---:200:200:404:404:200:---:---:---:---:---:---:---:404::Indy/9.0.11
404:404:---:404:404:404:---:404:404:---:---:---:404:404:404:200:404:+++:---:---:---:---:---:---:+++::Indy/9.00.10
HTM:200:500:HTM:200:HTM:HTM:505:HTM:HTM:HTM:HTM:200:200:302:+++:200:500:500:500:500:500:500:500:+++::Inktomi Search 4.2.0
# Internet Anywhere Admin Server (v.2.1-5.3?)
200:200:400:200:200:200:200:200:200:200:200:200:200:200:200:VER:200:400:400:400:400:400:400:400:200::Internet Anywhere WebServer [v2.1]
# Ipswitch
VER:200:501:VER:VER:VER:VER:VER:VER:501:501:501:---:200:200:404:400:---:501:501:501:501:501:501:200::Ipswitch-IMail/8.02
# Ipswitch older (obsolete?) signatures
HTM:200:501:HTM:HTM:HTM:HTM:HTM:HTM:501:501:501:---:200:200:404:400:---:501:501:501:501:501:501:+++:Ipswitch:Ipswitch Web Calendaring /8.04 or Ipswitch-IMail/8.04
200:200:---:200:200:200:---:404:404:---:---:---:---:200:200:200:200:---:---:---:---:---:---:---:+++::IMail_Monitor/8.04
400:200:405:400:200:400:400:400:400:200:400:200:500:200:401:+++:400:404:405:405:405:405:405:405:+++::Intel NMS 1.0
xxx:200:---:200:200:200:---:---:200:---:---:---:200:404:200:200:200:404:---:---:---:---:---:---:+++::IP_SHARER WEB 1.0 [Netgear Wireless router, WGR-614]
xxx:200:---:200:200:200:---:---:200:200:---:---:200:404:200:200:200:404:---:---:---:---:---:---:200::IP_SHARER WEB 1.0
# Version R14.2.15-3 (April 23rd, 1998). Debug level set to 0.
# 0 child process(es) active out of a maximum of 25.
# from Annex Corporation for a Xylogic serial annex server running on HP-UX.
200:200:---:200:200:200:200:---:200:200:200:200:200:200:200:---:200:---:---:---:---:---:---:---:200:^$:Security/boot server
500:200:501:200:200:200:500:405:200:500:500:500:200:200:200:200:200:404:405:405:405:405:405:405:200::Servertec-IWS/1.11
# SimpleHTTP from http://www.iki.fi/iki/src/index.html
HTM:302:HTM:HTM:302:HTM:HTM:302:HTM:302:HTM:HTM:302:404:404:404:302:404:HTM:HTM:HTM:HTM:HTM:HTM:404::SimpleHTTP/1.2
# Jana is seriously broken: it answers 200 to all requests. The real code is in the returned page, which is not HTTP conformant
# no404 partly fixes the signature.
200:200:200:200:200:200:200:200:200:200:200:200:200:200:200:200:200:404:404:404:404:404:404:404:404::Jana-Server/2.4.2
# Oracle?
HTM:200:200:505:---:400:400:501:200:400:HTM:400:200:400:400:+++:400:404:403:403:200:200:501:501:+++::JavaWebServer/2.0
404:404:501:404:404:404:400:501:404:404:501:400:404:404:404:+++:404:501:501:501:501:501:501:501:+++::Java Cell Server
400:200:400:200:200:200:400:400:200:400:400:400:---:400:400:400:200:400:400:400:400:400:400:400:+++:^$:JDMK4.1/Java2 Agent view on Windows 2000
# Jetty - I got the same sig for two versions
# Jetty/5.0.alpha3 (Linux/2.4.20-gentoo-r8 i386 java/1.4.1)
# Jetty/4.2.14 (Linux/2.4.20-gentoo-r8 i386 java/1.4.1)
HTM:200:200:200:200:200:---:200:200:---:---:---:200:404:302:+++:+++:404:404:404:404:200:404:404:200:Jetty/[45]\.:Jetty 4.2 or 5.0alpha
# JBoss (default installation, w/ no200)
HTM:200:200:200:200:200:---:200:200:---:---:---:200:404:404:+++:+++:100:100:404:404:200:405:405:404:Jetty/4\.:Jetty 4.2 in JBoss 3.0.6 (out of the box)
# also Jetty/4.2.9 (Windows 2000/5.0 x86 java/1.4.2)
HTM:200:200:200:200:200:---:200:200:---:---:---:200:404:404:+++:+++:404:404:404:404:200:405:405:404:Jetty/4\.:Jetty 4.2 in JBoss 3.2.1 (out of the box) or Jetty/4.2.9
xxx:200:200:503:503:503:xxx:500:503:200:HTM:xxx:200:400:400:400:400:200:200:200:200:200:200:200:200::Jetty/4.2.11 (Linux/2.4.20-8smp x86 java/1.4.1)
HTM:200:404:200:200:200:---:200:200:---:---:---:200:404:302:+++:400:100:100:404:404:200:404:404:+++::Jetty/4.1.4 (Windows XP 5.1 x86)
HTM:200:404:200:200:200:---:200:200:---:---:---:200:302:302:400:400:404:404:404:404:200:404:404:200::Jetty/4.2.9 (Windows 2003/5.2 x86 java/1.4.2_04)
#
HTM:200:200:200:---:HTM:---:501:---:200:---:---:200:404:404:+++:---:404:404:404:404:404:404:404:200:1\.0beta:Jigsaw 1.0beta2
HTM:200:200:200:---:HTM:---:501:---:200:---:---:200:404:404:+++:400:404:404:404:404:404:404:404:200::Jigsaw/2.0.5
HTM:200:200:200:---:HTM:---:501:---:200:---:---:200:404:404:+++:+++:404:404:404:404:200:404:404:200::Jigsaw/2.2.2
# More precise
HTM:200:200:200:---:HTM:---:501:---:200:---:---:200:404:404:404:400:404:404:404:404:200:404:404:200:^Jigsaw/2\.2\.[45]:Jigsaw/2.2.4-5
HTM:200:200:200:---:HTM:---:501:---:200:---:---:200:404:404:404:400:+++:400:404:404:200:404:404:+++::Jigsaw/2.2.4 [on Windows 2003 SP1]
400:404:200:200:404:400:400:400:400:400:400:400:404:400:400:400:404:405:200:200:200:200:200:200:404::Jigsaw 2.2.1 (Windows 2000)
400:404:404:200:404:400:400:400:400:400:400:400:404:400:400:400:404:405:404:404:404:404:404:404:404::Jigsaw 2.2.1(windows 2000)
HTM:301:200:200:---:HTM:---:501:---:301:---:---:301:301:301:301:400:404:404:404:404:200:404:404:301::Jigsaw/2.2.4
XML:200:200:200:---:XML:---:501:---:200:---:---:200:404:404:404:400:404:404:404:404:200:404:404:200::Jigsaw/2.2.5
# OS: Solaris 8 07/03 HW release, kernel patch 108528-27
# Web Server: Bundled with HP OpenView Performance Insight Version 4.6.0 GA, Service Pack 1
---:200:302:200:200:200:---:200:200:---:---:---:200:302:302:302:200:404:501:501:501:501:501:501:+++::JRun Web Server
# Kazaa - not a real web server
501:404:---:404:404:404:501:---:501:501:501:501:404:501:501:501:404:501:501:---:---:---:---:---:404:^$:Kazaa servent (not a real web server)
# Candle Web Server (Omegamon is a supervision/monitoring software)
# KDH/185.4 (v180_kbs4054a)
# KDH/185.4 (v180_kbs3348a)
# and also KDH/185.67?
---:200:404:---:---:---:---:200:---:200:---:---:200:404:404:404:200:404:404:404:404:404:---:---:200::KDH/185.4 [Candle Web Server from Omegamon]
# Less precise
# KDH/185.67 (v180_kbs4190a)
---:200:404:---:---:---:---:200:---:200:---:---:200:404:404:404:200:+++:404:404:404:404:---:---:+++::KDH/185 [Candle Web Server from Omegamon]
---:200:---:200:200:200:---:---:---:---:---:---:200:200:200:---:200:---:---:---:---:---:---:---:200::Kerio Personal Firewall
---:200:501:---:---:---:---:200:---:---:---:---:200:301:403:403:200:404:501:501:501:501:---:---:403:^KFWebServer/2\.5\.0 Windows:KFWebServer/2.5.0 on Windows 98 or NT4
# knobot-standalone-self-extracting-0.2.14.jar
XML:500:200:200:500:500:---:500:500:---:---:---:500:500:302:400:400:500:401:302:200:200:200:200:500::WYMIWYG RWCF (the KnoBot foundation) 0.3
# Linksys WRV54G wireless G router (with VPN)
# Hardware Version:  	   Rev.02
# Software Version: 	   2.37.1
HTM:200:501:200:400:400:400:200:400:200:400:400:200:400:400:400:400:400:501:501:501:501:501:501:+++:^$:Linksys WRV54G wireless router
HTM:200:400:200:200:200:400:200:200:200:400:400:200:400:400:400:200:404:400:400:400:400:400:400:HTM::LiteWeb/1.21
# LiteWeb/2.3
# LiteWeb/2.5
200:200:200:302:200:200:200:200:200:200:200:200:---:200:200:200:200:---:200:200:200:200:200:200:200::LiteWeb/2.
# Lotus Domino
HTM:200:200:200:200:200:HTM:200:HTM:200:HTM:HTM:200:200:403:+++:400:500:405:405:200:200:501:501:+++::Lotus-Domino/4.6
HTM:200:200:200:200:200:HTM:404:HTM:404:HTM:HTM:200:200:403:403:400:500:405:405:200:200:501:501:404::Lotus-Domino/Release-4.6.5
HTM:200:---:200:200:200:HTM:200:HTM:200:HTM:HTM:200:403:403:500:400:500:405:405:405:405:501:501:403::Lotus-Domino/5.0.5
HTM:200:405:200:200:200:HTM:200:HTM:200:HTM:HTM:200:403:403:500:400:500:405:405:405:405:501:501:500::Lotus-Domino/5.0.8
##HTM:200:405:200:200:200:HTM:200:HTM:200:HTM:HTM:200:200:403:500:400:500:405:405:405:405:501:501:+++::Lotus-Domino/5.0.11
# More precise
HTM:200:405:200:200:200:HTM:200:HTM:200:HTM:HTM:200:200:403:500:400:500:405:405:405:405:501:501:404::Lotus-Domino/5.0.3
# More precise 
# Lotus-Domino/5.0.8
# Lotus-Domino/0
HTM:200:405:200:200:200:HTM:200:HTM:200:HTM:HTM:200:200:403:500:400:500:405:405:405:405:501:501:500:^Lotus-Domino/(0|5\.0\.([89]|1[0-2]))$:Lotus Domino 5.0.8-12 [on Windows 2000 SP4 w/ AD?]
400:200:200:200:400:400:400:200:400:200:400:400:200:200:200:200:400:404:404:404:200:200:404:405:+++:^Lotus-Domino$:Lotus-Domino/R6.5
# Lotus Domino 6.5.1 for Win32 with interim fix 1 & spanish language pack installed in replace mode
400:---:200:200:400:400:400:200:400:200:400:400:200:200:200:200:400:404:405:405:200:200:405:405:200:^Lotus-Domino$:Lotus-Domino/R6.5.1IF1
# Domino-Go-Webserver/4.6.2.2
# Domino-Go-Webserver/4.6.2.51
HTM:200:200:200:200:200:HTM:HTM:HTM:200:HTM:HTM:200:200:403:403:400:500:405:405:200:200:501:501:404::Domino-Go-Webserver/4.6.2.
HTM:200:200:200:200:200:HTM:200:HTM:200:HTM:HTM:200:403:403:403:400:500:405:405:200:200:501:501:404::Domino-Go-Webserver/4.6.2.5
400:200:200:200:400:400:400:200:400:200:400:400:200:200:200:200:400:404:405:405:200:200:405:405:+++:^Lotus-Domino:Lotus-Domino/6.5.1 on Linux
#
200:200:501:200:200:200:404:501:200:404:404:404:---:404:404:404:200:---:501:501:501:501:501:501:404::EPSON-HTTP/1.0
HTM:200:501:200:200:HTM:xxx:200:200:200:HTM:200:---:302:404:+++:200:404:501:501:501:501:501:501:+++::LV_HTTP/1.0
HTM:200:---:200:---:---:---:---:---:200:---:200:---:200:200:+++:200:---:---:---:---:---:---:---:+++::LabVIEW/7.0
400:200:501:400:505:400:400:501:400:400:400:400:---:404:301:301:400:411:501:501:501:501:501:501:200::lighttpd/1.3.5 (Nov  3 2004/13:06:27)
400:200:200:400:505:400:400:501:400:400:400:400:---:404:200:200:400:411:501:501:200:501:501:501:200::lighttpd/1.3.16
400:200:501:400:505:400:400:501:400:400:400:400:---:400:301:301:400:411:501:501:501:501:501:501:200:lighttpd/1\.3\.1[01]:lighttpd/1.3.10-11
400:200:501:400:505:400:400:501:400:400:400:400:---:400:200:200:400:411:501:501:501:501:501:501:200:lighttpd/1\.3\.1[23]:lighttpd/1.3.12-13
400:200:200:400:505:400:400:501:400:400:400:400:---:404:200:200:400:411:404:404:200:501:501:501:200::lighttpd/1.4.0
400:200:200:505:400:400:400:501:400:400:400:400:---:404:200:200:400:411:404:404:200:501:404:501:200::lighttpd/1.4.11
# The banner is only: lighttpd
400:200:200:400:505:400:400:501:400:400:400:400:---:404:200:200:400:411:404:404:200:501:404:501:200::lighttpd/1.4.1
404:200:500:200:200:200:401:200:200:401:401:401:200:404:404:500:200:---:500:500:500:500:500:500:+++:^$:Linksys BEFW11S4 WAP - 1.44.2z, Dec 13 2002
200:200:501:200:200:200:400:400:400:400:400:400:200:404:404:+++:200:501:501:501:501:501:501:501:+++::LseriesWeb/1.0-beta (LSERIES)
HTM:302:HTM:HTM:HTM:HTM:HTM:HTM:HTM:302:HTM:HTM:HTM:HTM:HTM:---:HTM:404:HTM:HTM:HTM:HTM:HTM:HTM:404::LWS 0.1.2 [unconfigured]

200:200:400:200:200:200:400:200:200:400:400:400:---:400:400:+++:200:404:401:400:400:400:400:400:+++::PersonalNetFinder/1.0 ID/ACGI
# PersonalNetFinder/1.0 ID/ACGI
# MACOS_Personal_Websharing
200:200:400:200:200:200:400:200:200:400:400:400:---:400:400:+++:200:404:403:400:400:400:400:400:+++:MACOS_Personal_Websharing|PersonalNetFinder:MacOS PersonalNetFinder
HTM:200:HTM:200:200:---:HTM:HTM:200:200:HTM:HTM:200:HTM:HTM:+++:400:200:HTM:HTM:HTM:HTM:HTM:HTM:+++::AppleShareIP/6.0.0
HTM:200:HTM:200:200:---:HTM:HTM:200:200:HTM:HTM:200:HTM:HTM:---:400:404:HTM:HTM:HTM:HTM:HTM:HTM:HTM::AppleShareIP/6.3.2
#
HTM:200:501:xxx:HTM:HTM:HTM:HTM:HTM:200:HTM:HTM:200:404:301:301:400:404:501:501:501:501:501:501:200::HTTPi/1.4 (xinetd/Linux)
HTM:404:501:400:505:400:---:501:400:404:---:---:404:400:400:400:404:404:501:501:501:501:501:501:400::Mathopd/1.4p1
---:400:501:505:400:400:---:---:---:400:---:---:400:400:400:400:400:411:501:501:501:501:501:501:414::Mathopd/1.5b11
200:200:400:200:200:200:400:501:200:400:400:400:200:200:400:400:200:404:404:404:404:404:404:404:+++::Mdaemon Worldclient 2.06
# MERCUR Messaging 2005 version 5.0 (SP2) / 5.0.10.0
404:200:404:200:200:200:404:200:200:404:404:404:---:200:200:404:200:404:404:404:404:404:404:404:200::MERCUR Messaging 2005 [version 5.0 (SP2) / 5.0.10.0]
VER:VER:VER:VER:VER:VER:---:VER:VER:VER:---:---:---:VER:VER:VER:VER:VER:VER:VER:VER:VER:VER:VER:VER:^$:msfweb [Metasploit framework 2.5]
400:200:501:200:200:200:400:200:200:400:400:400:200:400:400:501:200:501:501:501:501:501:501:501:400::micro_httpd
# Snap Appliance, Inc./3.4.803
# Meridian Data/2.3.417
400:200:501:200:200:200:400:xxx:xxx:400:400:400:---:200:200:200:200:200:501:501:501:501:501:501:+++:^(Snap Appliance|Meridian Data):Quantum Snap Server
# model: 4000 series / OS: 3.4.790 (US) / Hardware: 2.2.1 / BIOS: 2.4.437
400:200:501:200:200:200:400:HTM:HTM:400:400:400:---:404:404:200:200:404:501:501:501:501:501:501:400::Quantum Corporation./3.4.790
# Quantum Corporation./3.4.790
# Snap Appliances, Inc./3.1.618
400:200:501:200:200:200:400:HTM:HTM:400:400:400:---:200:200:200:200:404:501:501:501:501:501:501:400:^(Snap Appliance|Quantum Corporation):Quantum Snap Server
# Belkin 54g Wireless AP model F5D7130 - version 1000
---:200:501:200:200:200:---:200:200:---:---:---:200:400:400:501:200:404:501:501:501:501:501:501:+++::micro_httpd
HTM:200:400:200:200:200:400:400:200:400:400:400:---:404:404:+++:200:400:501:501:400:400:400:501:+++::Micro-HTTP/1.0
HTM:200:501:200:200:200:400:501:200:400:400:400:200:404:404:+++:200:400:501:501:501:501:501:501:+++::Micro-HTTP/1.0
HTM:200:501:200:200:200:400:501:200:400:400:400:200:404:404:+++:200:400:501:501:501:501:501:HTM:+++::Micro-HTTP/1.0
HTM:200:501:200:200:200:400:HTM:200:400:400:400:200:404:404:+++:200:400:HTM:501:HTM:HTM:HTM:HTM:+++::Micro-HTTP/1.0
HTM:200:501:200:200:200:400:501:200:400:400:400:200:404:404:+++:200:400:HTM:501:501:HTM:HTM:501:+++::Micro-HTTP/1.0
HTM:200:HTM:200:200:200:400:HTM:200:400:400:400:200:404:404:+++:200:400:HTM:HTM:501:501:501:HTM:+++::Micro-HTTP/1.0
# MS IIS
HTM:200:404:200:200:HTM:400:501:HTM:200:400:400:200:200:404:404:200:501:501:501:501:501:501:501:200:^Microsoft-IIS/[23]\.0:Microsoft-IIS/2 or Microsoft-IIS/3
# MS PWS (old sig)
##HTM:200:404:200:200:HTM:400:501:HTM:200:400:400:200:200:404:+++:200:501:501:501:501:501:501:501:+++::Microsoft-PWS/3.0
200:200:200:200:200:200:400:400:400:400:400:400:200:400:400:400:400:405:403:403:200:200:501:501:200:^Microsoft-IIS/4\.0:Microsoft-IIS/4 on Win98SE [PWS]
#
HTM:200:200:200:200:HTM:400:400:400:400:400:400:200:400:400:+++:+++:405:411:404:200:200:501:501:+++::Microsoft-IIS/4.0
HTM:200:200:200:200:HTM:400:404:400:400:400:400:200:400:400:400:400:405:404:404:200:404:404:404:200::Microsoft-IIS/4.0
HTM:200:200:200:200:HTM:400:400:400:400:400:400:200:400:400:400:400:405:403:403:200:200:501:501:200::Microsoft-IIS/4.0 [on Windows NT4 SP6a, or MS PWS on Windows 98]
404:200:501:200:200:200:501:501:200:200:501:---:200:---:200:501:200:405:501:501:501:501:501:501:200::Microsoft-IIS/5.0 [on Windows Server 2003 SP 1]
404:404:200:200:404:404:400:400:400:400:400:400:404:400:400:+++:+++:405:501:501:200:200:501:501:+++::Microsoft-IIS/5.0
404:404:200:200:404:404:400:400:400:400:400:400:404:400:400:+++:404:405:411:404:200:200:400:411:+++::Microsoft-IIS/5.0
200:200:200:200:200:200:400:400:400:400:400:400:200:400:400:400:400:405:501:501:200:200:501:501:200::Microsoft-IIS/5.0
HTM:200:200:200:200:HTM:400:400:400:400:400:400:200:400:400:400:400:405:404:404:200:404:404:404:200::Microsoft-IIS/5.0
200:200:404:VER:200:200:400:400:400:400:400:400:200:400:400:400:400:405:404:404:404:404:404:404:200::Microsoft-IIS/5.0 (Using iHTML/2.20.8)
## Might be IIS-4 or IIS-5?? I don't like that. I suspect I was given wrong information
# IIS-5 w/ ASP.net
200:200:404:200:200:200:400:400:400:400:400:400:200:400:400:400:400:405:404:404:404:404:404:404:200::Microsoft-IIS/5.0
# Same as above, imprecise
# X-Powered-By: ASP.NET - X-Powered-By: PHP/4.3.2
200:200:404:200:200:200:400:400:400:400:400:400:200:400:400:400:400:405:404:404:404:404:404:404:+++::Microsoft-IIS/5.1
##200:200:404:200:200:200:400:400:400:400:400:400:200:400:400:+++:400:405:404:404:404:404:404:404:+++::Microsoft-IIS/5.0 
# w/ PHP and ASP.NET?
404:404:200:200:404:404:400:400:400:400:400:400:404:400:400:400:404:405:403:403:200:200:400:411:404::Microsoft-IIS/5.0
200:200:200:200:200:200:400:400:400:400:400:400:200:400:400:400:200:200:403:403:200:200:403:403:200::Microsoft-IIS/5.0 w/ ASP.NET
# old sig  - There is a similar signature below
##200:200:200:200:200:200:400:400:400:400:400:400:200:400:400:+++:400:405:403:403:200:404:400:411:+++::Microsoft-IIS/5.0
HTM:200:200:200:200:HTM:400:400:400:400:400:400:200:400:400:+++:400:405:411:404:200:200:400:411:+++::Microsoft-IIS/5.0
# Somebody got the same signature w/ URLScan
200:200:200:200:200:200:400:400:400:400:400:400:200:400:400:400:400:200:200:200:200:200:200:200:+++:^Microsoft-IIS/5\.0$:Microsoft-IIS/5.0 (Windows 2000 server SP4 w/ latest patches [2003-02-05])
403:403:200:200:403:403:400:400:400:400:400:400:403:400:400:400:400:405:501:501:200:200:501:501:403:^Microsoft-IIS/5\.0$:Microsoft-IIS/5.0 (Windows 2000 SP3 w/ iislockdown & urlscan)
# Suspicious signature
404:404:404:200:404:404:400:400:400:400:400:400:404:400:400:400:404:405:404:404:404:404:404:404:404:Microsoft-IIS/5\.0:Microsoft-IIS/5.0 w/ URLScan 2.5 (6.0.3615.0) on Win2000 server up to date (2004-01-14)
# Windows 2000 server SP4 w/ urlscan, w/o OWA
HTM:200:404:200:200:HTM:---:400:400:400:400:400:200:400:400:400:400:404:404:404:404:404:404:404:+++:Microsoft-IIS/5\.0:Microsoft-IIS/5.0 with UrlScan, without Outlook Web Access, on Win2000 SP4
#
# MS IIS 5.0 with UrlScan allowing all ASP pages, without Outlook Web Access, on Win2000 SP4
# or:
# Windows 2000 Server 5.0.2195 Service Pack 4 Build 2195
# Microsoft Exchange Server Version 5.5 (Build 2653.23: Service Pack 4)
# UrlScan with Outlook Web Access
#
HTM:200:404:200:200:HTM:400:400:400:400:400:400:200:400:400:400:400:405:404:404:404:404:404:404:+++:^Microsoft-IIS/5\.0$:Microsoft-IIS/5.0 with UrlScan
# What do I do with this?
#HTM:200:404:200:200:HTM:400:400:400:400:400:400:200:400:400:400:400:405:404:404:404:404:404:404:200:FIXME:Microsoft-IIS/4.0
#
# Windows 2000, SP3? 4? w/o the latest patches
#200:200:400:200:200:200:400:400:400:400:400:400:200:400:400:400:400:405:403:403:200:200:400:411:+++::Microsoft-IIS/5.0
# More precise
200:200:400:200:200:200:400:400:400:400:400:400:200:400:400:400:400:405:403:403:200:200:400:411:200::Microsoft-IIS/5.0
# X-Powered-By: ASP.NET
# Windows 2000 Advanced Server, SP-4 Build 2195; IIS5 with .NET
200:200:200:200:200:200:400:400:400:400:400:400:200:400:400:400:400:405:403:403:200:404:400:411:+++:Microsoft-IIS/5\.0:Microsoft-IIS/5.0 with .NET on Win2000 SP4
200:200:200:200:200:200:400:400:400:400:400:400:200:400:400:400:400:405:403:403:200:200:400:411:200:^Microsoft-IIS/5\.[01]:Microsoft-IIS/5.0 on Win2000 SP4 or 5.1 on WinXP SP1
# IIS 5.0 on Win 2000 SP4 server english with all patches (2003-12-16) & .NET & without Lockdown
xxx:200:200:200:200:xxx:400:400:400:400:400:400:200:400:400:400:400:405:403:403:200:200:400:411:+++:^Microsoft-IIS/5\.0:Microsoft-IIS/5.0 with .NET on Win2000 SP4
HTM:200:200:200:200:HTM:400:400:400:400:400:400:200:400:400:400:400:405:403:403:200:404:400:411:404::Microsoft-IIS/5.0
HTM:200:200:200:200:HTM:400:400:400:400:400:400:200:400:400:400:400:405:501:501:200:200:501:501:200::Microsoft-IIS/5.0
HTM:200:200:200:200:HTM:400:400:400:400:400:400:200:400:400:400:400:405:403:403:200:200:400:411:200:^Microsoft-IIS/5\.0:Microsoft-IIS/5.0 on Win2000 with latest patches (2003-12-29)
200:200:200:200:200:200:400:400:400:400:400:400:200:400:400:400:400:405:411:404:200:200:400:411:200::Microsoft-IIS/5.0
# The next signature is too imprecise and clashes the previous IIS/5.0 signature
##HTM:200:500:200:200:HTM:400:400:400:400:400:400:200:400:400:400:400:405:500:500:500:200:500:500:200::Microsoft-IIS/5.
# And also this one?
##HTM:200:200:200:200:HTM:400:400:400:400:400:400:200:400:400:+++:+++:405:403:403:200:200:400:411:+++:Microsoft-IIS/5\.1:Microsoft-IIS/5.1 on WinXP
HTM:200:500:200:200:HTM:400:400:400:400:400:400:200:400:400:+++:400:405:500:500:500:200:500:500:+++::Microsoft-IIS/5.1
200:200:500:200:200:200:400:400:400:400:400:400:200:400:400:400:400:405:500:500:500:200:500:500:200::Microsoft-IIS/5.1
# IIS 5, Windows 2000 SP-4 running OWA on exchange 5.5
400:200:404:200:200:400:400:400:400:400:400:400:200:400:400:400:400:405:404:404:404:404:404:404:200:^$:Microsoft-IIS/5 (OWA on Exchange 5.5)
# Unpatched IIS 5.0 protected by Checkpoint Firewall-1 Smart Defense
xxx:200:200:200:200:xxx:---:400:400:---:---:---:200:400:400:400:400:405:403:403:200:200:400:400:+++:Microsoft-IIS/5\.0:Microsoft-IIS/5.0 (behind FW-1)
# IIS/6
HTM:200:200:505:400:400:400:400:400:200:400:400:200:400:400:400:400:411:411:501:200:501:501:501:200::Microsoft-IIS/6.0 [on Windows 2003 SP1]
HTM:200:200:505:400:400:400:400:400:200:400:400:200:400:400:400:400:411:411:403:200:501:400:411:200::Microsoft-IIS/6.0 [on Windows 2003 SP1]
xxx:200:200:505:400:---:400:400:400:200:400:400:---:400:400:400:400:411:411:501:200:501:501:501:200::Microsoft-IIS/6.0 [w/ ASP.NET]
HTM:200:200:505:400:---:400:400:400:200:400:400:---:400:400:+++:400:411:411:501:200:501:501:501:+++::Microsoft-IIS/6.0
200:200:200:505:400:---:400:400:400:200:400:400:---:400:400:400:400:411:411:404:200:501:400:411:200::Microsoft-IIS/6.0
200:200:200:505:400:---:400:400:400:200:400:400:---:400:400:+++:400:411:411:403:200:501:400:411:+++:Microsoft-IIS/6\.0:Microsoft-IIS/6.0 [w/ ASP.NET 1.1.4322]
200:200:200:505:400:---:400:400:400:200:400:400:---:400:400:400:400:411:411:501:200:501:501:501:200:^Microsoft-IIS/6\.0$:Microsoft-IIS/6.0 [w/ ASP.NET on Windows 2003]
HTM:200:---:505:400:400:400:400:400:200:400:400:200:400:400:400:400:411:411:404:404:501:404:404:200::Microsoft-IIS/6.0 [w/ ASP.NET on Windows 2003 SP1]
HTM:200:200:505:400:---:400:400:400:200:400:400:---:400:400:400:400:411:411:403:200:501:400:411:200::Microsoft-IIS/6.0 [w/ ASP.NET on Windows 2003]
HTM:200:200:505:400:400:400:400:400:200:400:400:200:400:400:400:400:411:411:404:200:501:400:411:200::Microsoft-IIS/6.0 [w/ ASP.NET on Windows 2003 SP1]
200:200:200:505:400:400:400:400:400:200:400:400:200:400:400:400:400:411:411:501:200:501:501:501:200::Microsoft-IIS/6.0 [w/ ASP.NET on Windows 2003 SP1]
200:200:200:505:400:400:400:400:400:200:400:400:200:400:400:400:400:411:411:403:200:501:400:411:200::Microsoft-IIS/6.0
HTM:200:200:505:400:---:400:400:400:200:400:400:---:400:400:400:400:411:411:200:200:200:200:200:200::Microsoft-IIS/6.0 [w/ ASP.NET on Windows 2003]
HTM:200:200:505:400:---:400:400:400:200:400:400:---:400:400:400:400:411:411:501:200:501:501:501:200::Microsoft-IIS/6.0 [w/ ASP.NET on Windows 2003]
# MS ISA Server 2000
400:403:500:403:400:400:400:400:400:403:400:400:403:500:500:500:403:403:403:403:403:403:403:403:403:^$:MS ISA Server 2000 reverse proxy (rejecting connections)
# MS ISA 2004
400:200:500:200:400:400:400:400:400:200:400:400:200:500:500:500:200:411:411:501:200:200:501:501:+++::Microsoft-IIS/6.0 [w/ .NET; through MS ISA Server 2004 Beta2]
# Mini HTTPD
xxx:200:501:VER:VER:VER:xxx:VER:xxx:200:xxx:xxx:200:400:400:400:200:404:501:501:501:501:501:501:400:mini_httpd/1\.1[78]:mini_httpd/1.17beta1 or 1.18
# Also ECL-WebAdmin/1.0 [Embedded Coyote Linux on Linux 2.4.23] from www.coyotelinux.com
HTM:200:501:VER:VER:VER:HTM:VER:HTM:200:HTM:HTM:200:400:400:400:200:404:501:501:501:501:501:501:400::mini_httpd/1.19 19dec2003
#
400:200:400:400:200:400:400:400:400:200:400:400:200:200:200:+++:200:200:400:400:400:400:400:400:+++::MiniServ/0.01
---:200:---:---:200:---:---:---:---:200:---:---:200:200:200:200:200:200:---:---:---:---:---:---:+++::MiniServ/0.01
---:200:200:200:200:200:---:200:200:---:---:---:200:200:200:200:200:200:200:200:200:200:200:200:200::MLdonkey
# Monkey
#400:200:403:200:200:200:400:405:200:400:400:400:200:404:404:+++:+++:411:405:405:405:405:405:405:+++::Monkey/0.7.1 (Linux)
# Same as above - more precise
400:200:403:200:200:200:400:405:200:400:400:400:200:404:404:403:400:411:405:405:405:405:405:405:403::Monkey/0.8.2 (Linux)
400:200:403:200:200:200:400:405:200:400:400:400:200:404:404:403:200:411:405:405:405:405:405:405:403::Monkey/0.9.1 (Linux)
#
302:302:501:302:302:302:404:302:302:302:501:302:100:404:401:401:302:404:401:401:501:501:501:501:400::MyServer 0.6.2
302:302:200:302:302:302:302:302:302:302:200:200:---:200:200:200:302:---:---:401:200:200:200:200:302::MyServer 0.7
#
---:---:---:200:---:---:---:---:---:---:---:---:---:---:---:---:---:404:404:404:---:404:---:---:+++:PLT Scheme:mzserver 203-6 on Debian 
# aEGiS_nanoweb/2.1.3 (Linux; PHP/4.3.3)
# aEGiS_nanoweb/2.2.0 (Linux; PHP/4.3.3)
# aEGiS_nanoweb/2.2.1 (Linux; PHP/4.3.3)
200:200:200:200:200:200:200:501:200:501:501:200:200:404:302:404:200:404:501:501:200:501:501:501:200:^aEGiS_nanoweb/2\.(1\.3)|(2\.[01]):aEGiS_nanoweb/2.1.3 or 2.2.0 or 2.2.1
400:200:200:200:200:200:400:501:400:501:501:400:200:404:302:404:200:404:501:501:200:501:501:501:200::aEGiS_nanoweb/2.2.2 (Linux; PHP/4.3.3)
# Good old NCSA
HTM:200:400:200:200:200:HTM:400:200:HTM:HTM:HTM:200:404:404:302:200:501:400:400:400:400:400:400:---::NCSA/1.1
# NCSA/1.2
# NCSA/1.4.2
HTM:200:400:200:200:200:HTM:400:200:HTM:HTM:HTM:200:404:404:302:200:404:404:404:400:400:400:400:---:^NCSA/1\.([234]):NCSA/1.2 to 4.2
HTM:200:400:200:200:200:HTM:HTM:200:200:400:HTM:200:404:404:301:200:404:404:404:400:400:400:400:200::NCSA/1.5
HTM:200:HTM:HTM:HTM:HTM:400:HTM:HTM:200:HTM:400:200:404:404:+++:+++:404:404:404:400:400:400:400:+++::NCSA/1.5.2
HTM:200:400:HTM:HTM:HTM:400:400:HTM:200:HTM:400:200:404:404:+++:200:404:404:404:400:400:400:400:+++::NCSA/1.5.2
400:200:400:200:400:400:400:400:400:200:400:400:200:400:400:400:200:411:411:404:400:400:400:400:200::NCSA/1.5.2 thru proxy cache
200:200:---:200:200:200:---:200:200:---:---:200:---:404:404:---:200:+++:---:---:---:---:---:---:+++::Netgear
# nginx/0.1.24
# nginx/0.1.26
# nginx/0.1.28
# nginx/0.1.37
# nginx/0.1.41
# nginx/0.1.45
# nginx/0.2.6
# nginx/0.3.7
# nginx/0.3.9
HTM:200:HTM:200:HTM:HTM:HTM:HTM:HTM:HTM:HTM:HTM:200:HTM:HTM:HTM:400:400:405:405:405:405:405:405:200:^nginx/0\.[1-3]\.[0-9]+$:nginx/0.1.24-0.3.9
# www-servers/nginx-0.3.35  -debug -fastcgi -imap +pcre -perl +ssl +threads* +zlib
HTM:200:HTM:200:HTM:HTM:HTM:HTM:HTM:HTM:HTM:HTM:200:HTM:HTM:HTM:400:411:405:405:405:405:405:405:200::nginx/0.3.35
# 403 on /
HTM:403:HTM:403:HTM:HTM:HTM:HTM:HTM:HTM:HTM:HTM:403:HTM:HTM:HTM:400:400:405:405:405:405:405:405:403:^nginx/0\.1\.2[4-8]:nginx/0.1.24-28 [broken configuration]
200:200:400:200:200:200:400:200:200:400:400:400:200:400:400:+++:200:400:400:400:400:400:400:400:+++::NUD/3.6
400:200:501:400:400:400:400:400:400:400:400:400:400:400:400:+++:200:501:501:501:501:501:501:501:+++::NUD/4.0.3
200:200:---:200:200:200:---:---:---:---:---:---:200:200:200:+++:200:200:---:---:---:---:---:---:+++::NetPresenz/4.1
########
# Netscape-Enterprise/3.0
# Netscape-Enterprise/3.5.1G
# Netscape-FastTrack/3.01B
HTM:200:200:200:200:200:400:500:200:200:400:200:200:404:404:404:200:500:401:401:200:200:500:400:404:^Netscape-(Enterprise|FastTrack)/3\.[025]:Netscape-Enterprise/3.0 to 3.5.1G or Netscape-FastTrack/3.01B
# Netscape-Enterprise/3.0L
# Netscape-Enterprise/3.5.1G
# Netscape-Enterprise/3.6 SP2
HTM:200:200:400:200:200:400:500:200:400:400:400:200:404:404:404:400:500:401:401:200:200:500:400:404:^Netscape-Enterprise/3.[06]:Netscape-Enterprise/3.0L to 3.6 SP2
# Netscape-Enterprise/4.1
HTM:200:200:505:HTM:HTM:HTM:501:HTM:200:HTM:HTM:200:HTM:HTM:HTM:400:405:404:404:200:200:501:501:200::Netscape-Enterprise/4.1
HTM:200:200:505:HTM:HTM:HTM:501:HTM:200:HTM:HTM:200:HTM:HTM:HTM:400:405:401:401:200:200:501:501:200:^Netscape-Enterprise/[46]\.[01]:Netscape-Enterprise/4.1 to 6.0
# Netscape Enterprise 4.1 SP14 Administration web server (8888) on Windows 2000 Advanced Server with SP4
HTM:200:200:505:HTM:HTM:HTM:501:HTM:200:HTM:HTM:200:HTM:HTM:HTM:400:200:200:200:200:200:501:501:200::Netscape-Enterprise/4.1 [SP7 - SP14]
# Netscape-Enterprise/6.0
# Sun-ONE-Web-Server/6.1
HTM:200:200:505:HTM:HTM:HTM:501:HTM:200:HTM:HTM:200:HTM:HTM:HTM:400:404:401:401:200:200:501:501:200:^(Netscape-Enterprise/(4\.1|6\.0)|Sun-ONE-Web-Server/6\.1):Netscape-Enterprise/4.1 to 6.1 (Sun-ONE-Web-Server)
HTM:200:200:505:HTM:HTM:HTM:501:HTM:200:HTM:HTM:200:HTM:HTM:HTM:400:404:405:405:200:200:501:501:200::Netscape-Enterprise/6.1 AOL
HTM:200:200:505:HTM:HTM:HTM:501:HTM:200:HTM:HTM:200:HTM:HTM:HTM:400:405:401:401:200:405:501:501:200::Sun-ONE-Web-Server/6.1
# Sun One Web Server 6.1 on Sun Solaris 8
HTM:500:200:505:HTM:HTM:HTM:501:HTM:500:HTM:HTM:500:HTM:HTM:HTM:400:+++:401:401:200:200:501:501:+++::Sun-ONE-Web-Server/6.1
##HTM:200:200:505:HTM:HTM:HTM:501:HTM:200:HTM:HTM:200:HTM:HTM:+++:400:404:405:405:200:200:501:501:+++::Sun-ONE-Application-Server/7.0.0_01
# Netscape-Communications/1.1
# Netscape-Communications/2.01
# Netscape-Communications/2.01c
# Netscape-Enterprise/2.0a
# Netscape-Enterprise/2.0d
# Netscape-FastTrack/2.01
# Netscape-FastTrack/2.01a
# Netscape-FastTrack/2.0a
# Netscape-Commerce/1.12
HTM:200:404:200:200:200:400:500:200:400:400:400:200:404:404:404:200:500:500:500:500:500:500:500:404:^Netscape-(Commerce|Communications|Enterprise|FastTrack)/(1\.1|2\.0):Netscape/1.1 to 2.01c
---:200:400:200:200:200:400:405:200:400:400:400:200:400:400:400:200:---:---:500:405:405:405:405:404::Netscape-Enterprise/3.6
# Is this reliable?
HTM:200:200:400:400:400:400:400:400:400:400:400:200:404:404:404:400:404:404:404:200:200:404:404:404::Netscape-Enterprise/3.6 SP3
200:200:200:400:400:HTM:HTM:500:HTM:200:HTM:HTM:200:HTM:HTM:HTM:400:404:401:401:200:200:500:404:404::Netscape-Enterprise/4.0
200:200:200:505:HTM:HTM:HTM:501:HTM:200:HTM:HTM:200:HTM:HTM:HTM:400:404:401:401:200:200:501:501:200::Netscape-Enterprise/4.1
200:200:200:505:HTM:HTM:HTM:501:HTM:200:HTM:HTM:200:HTM:HTM:HTM:400:405:401:401:200:200:501:501:200::Netscape-Enterprise/4.1
200:200:200:505:HTM:HTM:HTM:501:HTM:200:HTM:HTM:200:HTM:HTM:HTM:400:405:405:405:200:200:501:501:200::Netscape-Enterprise/4.1
HTM:200:200:200:200:400:400:400:400:200:400:200:200:404:404:404:200:404:401:401:200:200:404:404:404::Netscape-Enterprise/3.6 SP2
HTM:200:200:200:200:400:400:400:400:200:400:200:200:404:404:404:200:500:401:401:200:200:500:400:404:^Netscape-Enterprise/3.6( SP1)?$:Netscape-Enterprise/3.6 or 3.6 SP1
HTM:200:200:200:200:400:400:400:400:200:400:200:200:404:404:404:200:500:500:500:200:200:500:500:404::Netscape-Enterprise/3.6 SP3
HTM:200:200:400:400:400:400:400:400:400:400:400:200:404:404:404:400:404:401:401:200:200:400:404:404::Netscape-Enterprise/3.6 SP3
HTM:200:200:400:200:200:400:500:200:400:400:400:200:200:404:404:400:500:401:401:200:200:500:400:404::Netscape-FastTrack/3.01
HTM:200:200:400:400:400:400:400:400:400:400:400:200:200:404:404:400:500:401:401:200:200:500:400:404:^Netscape-Enterprise/3.6( SP1)?$:Netscape-Enterprise/3.6 or 3.6 SP1
HTM:200:200:400:400:400:400:400:400:400:400:400:200:200:404:404:400:500:401:401:200:200:500:404:404::Netscape-Enterprise/3.6 SP2
HTM:200:200:400:400:400:400:400:400:400:400:400:200:---:---:---:400:500:401:401:200:200:500:404:404::Netscape-Enterprise/3.6 SP2
HTM:200:200:400:400:400:400:400:400:400:400:400:200:404:404:404:400:500:401:401:200:200:400:404:404::Netscape-Enterprise/3.6 SP3
HTM:200:200:400:400:400:400:400:400:400:400:400:200:404:404:404:400:500:401:401:200:200:500:400:404::Netscape-Enterprise/3.6
HTM:200:200:400:400:400:400:400:400:400:400:400:200:404:404:404:400:500:500:500:200:200:500:400:404::Netscape-Enterprise/3.6
HTM:200:200:400:400:400:400:400:400:400:400:400:200:404:404:404:400:500:500:500:200:200:500:500:404::Netscape-Enterprise/3.6 SP2
HTM:200:200:400:400:HTM:HTM:500:HTM:200:HTM:HTM:200:HTM:HTM:HTM:400:404:401:401:200:200:500:404:404::Netscape-Enterprise/4.0
HTM:200:200:400:400:HTM:HTM:500:HTM:200:HTM:HTM:200:HTM:HTM:HTM:400:404:500:500:200:200:500:500:404::Netscape-Enterprise/4.0
HTM:200:200:505:HTM:HTM:---:501:HTM:200:HTM:---:200:HTM:HTM:HTM:400:404:401:401:200:200:501:501:200::Netscape-Enterprise/4.1
HTM:200:200:505:HTM:HTM:---:501:HTM:200:HTM:---:200:HTM:HTM:HTM:400:404:405:405:200:200:501:501:200::Netscape-Enterprise/6.0
HTM:200:200:505:HTM:HTM:---:501:HTM:200:HTM:---:200:HTM:HTM:HTM:400:405:401:401:200:200:501:501:200::Netscape-Enterprise/4.1
HTM:200:200:505:HTM:HTM:---:501:HTM:200:HTM:---:200:HTM:HTM:HTM:400:405:405:405:200:200:501:501:200::Netscape-Enterprise/4.1
HTM:200:200:505:HTM:HTM:HTM:501:HTM:200:HTM:HTM:200:HTM:HTM:HTM:400:404:401:401:200:413:501:501:200:^Netscape-Enterprise/(4\.1|6\.0):Netscape-Enterprise/4.1 or 6.0
HTM:200:200:505:HTM:HTM:HTM:501:HTM:200:HTM:HTM:200:HTM:HTM:HTM:400:404:404:404:200:200:501:501:200::Netscape-Enterprise/4.1
HTM:200:200:505:HTM:HTM:HTM:501:HTM:200:HTM:HTM:200:HTM:HTM:HTM:400:405:401:401:200:413:501:501:200:^Netscape-Enterprise/(4\.1|6\.0):Netscape-Enterprise/4.1 SP12 or 6.0
HTM:200:200:505:HTM:HTM:HTM:501:HTM:200:HTM:HTM:200:HTM:HTM:HTM:400:405:403:403:200:200:501:501:200::Netscape-Enterprise/6.0
HTM:200:200:505:HTM:HTM:HTM:501:HTM:200:HTM:HTM:200:HTM:HTM:HTM:400:405:404:404:200:200:400:501:200::Netscape-Enterprise/4.1
HTM:200:200:505:HTM:HTM:HTM:501:HTM:200:HTM:HTM:200:HTM:HTM:HTM:400:405:405:405:200:200:501:501:200::Netscape-Enterprise/4.1
HTM:200:404:200:200:200:400:200:200:200:400:200:200:200:404:404:200:500:500:500:500:500:500:500:404::Netscape-Enterprise/2.01c
HTM:200:404:400:200:200:400:500:200:400:400:400:200:404:404:404:200:500:500:500:500:500:500:500:404::Netscape-Enterprise/3.5.1G
HTM:200:---:505:HTM:HTM:---:---:HTM:---:---:---:---:---:---:---:400:405:401:---:---:---:---:---:200::Netscape-Enterprise/4.1
HTM:200:---:505:HTM:HTM:---:---:HTM:---:---:---:---:HTM:HTM:HTM:400:404:401:---:---:---:---:---:200::Netscape-Enterprise/6.0
XML:200:200:505:HTM:HTM:HTM:501:HTM:200:HTM:HTM:200:HTM:HTM:HTM:400:404:401:401:200:200:501:501:200:^Netscape-Enterprise/(4\.1|6\.0):Netscape-Enterprise/4.1 or 6.0
#
HTM:200:404:200:200:200:---:200:200:200:400:200:200:200:404:+++:+++:500:500:500:500:500:500:500:+++::Netscape-Enterprise/3.5-For-NetWare
HTM:200:404:200:200:200:400:200:200:200:400:200:200:200:404:404:200:500:401:401:500:500:500:404:404::Netscape-Enterprise/3.5-For-NetWare
HTM:200:200:200:200:400:400:400:400:200:400:200:200:404:404:+++:200:---:401:401:200:200:---:404:+++::Netscape-Enterprise/3.6 SP3
HTM:200:200:400:400:400:400:400:400:400:400:400:200:404:404:+++:400:500:401:401:200:200:500:404:+++::Netscape-Enterprise/3.6 SP3
HTM:200:200:400:400:400:400:400:400:400:400:400:200:404:404:404:400:404:401:401:200:200:404:404:404::Netscape-Enterprise/3.6 SP3
HTM:200:200:200:200:400:400:400:400:200:400:200:200:404:404:404:200:500:401:401:200:200:500:404:404:^Netscape-Enterprise/3\.6 SP[23]$:Netscape-Enterprise/3.6 SP2 or SP3
HTM:200:200:200:200:400:400:400:400:200:400:200:200:200:404:404:200:500:404:404:200:200:500:404:404::Netscape-Enterprise/3.6 SP2
HTM:200:200:200:200:400:---:400:400:200:400:---:200:404:404:404:200:500:404:404:200:200:500:404:404::Netscape-Enterprise/3.6 SP3
# Solaris 8
HTM:200:200:500:500:xxx:xxx:500:xxx:200:xxx:xxx:200:xxx:xxx:xxx:400:404:401:401:200:200:500:404:+++:Netscape-Enterprise/4.0 [Sun Solaris 8]
HTM:200:200:200:HTM:HTM:HTM:200:HTM:200:HTM:HTM:200:HTM:HTM:+++:+++:200:200:200:200:200:200:200:+++:Netscape-Enterprise/6\.0:SunONE 6.0 on Solaris 7
# Which SP?
200:200:200:505:HTM:HTM:---:501:HTM:200:---:---:200:HTM:HTM:---:400:405:401:401:200:200:501:501:200::Netscape-Enterprise/4.1 (which SP?)
HTM:401:200:505:HTM:HTM:HTM:501:HTM:401:HTM:HTM:401:HTM:HTM:+++:+++:401:401:401:401:200:501:501:401:Netscape-Enterprise/4\.1:Netscape Enterprise 4.1 SP13 console (access denied) on Linux
HTM:200:200:505:HTM:HTM:HTM:501:HTM:200:HTM:HTM:200:HTM:HTM:+++:+++:405:401:401:200:200:501:501:200:Netscape-Enterprise/(4\.1|6\.0):iPlanet 4.1 SP13 or SunONE 6.0 SP1/SP6 on Linux
HTM:401:200:505:HTM:HTM:HTM:501:HTM:401:HTM:HTM:401:HTM:HTM:+++:+++:500:500:500:500:200:501:501:401:Netscape-Enterprise/6\.0:SunONE 6.0 SP1 or SP6 console (access denied) on Linux
HTM:302:200:505:HTM:HTM:HTM:501:HTM:302:HTM:HTM:302:HTM:HTM:+++:+++:500:500:500:500:200:501:501:401:Netscape-Enterprise/6\.0:SunONE 6.0 SP1 or SP6 console (access granted) on Linux
HTM:200:200:505:HTM:HTM:HTM:501:HTM:500:HTM:HTM:200:HTM:HTM:HTM:400:405:401:401:200:200:501:501:+++:^Netscape-Enterprise/4\.1:iPlanet/4.5 SP10 on AIX
# Conflict with previous (less precise) signature
HTM:200:200:505:HTM:HTM:HTM:501:HTM:200:HTM:HTM:200:HTM:HTM:HTM:400:404:401:401:200:200:501:501:+++::Netscape-Enterprise/6.0
# Broken banner?
HTM:200:200:505:HTM:HTM:HTM:501:HTM:200:HTM:HTM:200:HTM:HTM:HTM:400:404:401:401:200:501:501:501:+++:.USBR.:SunONE 6.1 on Solaris 8
##HTM:200:200:505:HTM:HTM:HTM:501:HTM:200:HTM:HTM:200:HTM:HTM:+++:400:404:405:405:200:200:501:501:+++::Sun-ONE-Application-Server/7.0.0_01
HTM:200:200:200:---:---:---:HTM:HTM:---:---:---:200:200:200:200:---:405:401:401:200:200:501:501:200::Netscape-Enterprise/6.0 thru NetCache NetApp/5.5R4D6
#
302:200:200:200:200:200:501:501:200:501:501:501:200:302:302:302:200:404:404:404:200:501:501:501:302::NetServe/1.0.41
#
HTM:200:404:200:200:400:400:403:200:200:400:200:200:200:404:404:200:500:403:403:403:200:403:403:+++::NetWare-Enterprise-Web-Server/5.1
HTM:200:404:200:400:400:400:403:200:400:400:400:200:200:404:404:400:500:403:403:403:200:403:403:+++::NetWare-Enterprise-Web-Server/5.1
HTM:200:404:200:200:400:400:400:400:200:400:200:200:200:404:404:200:500:401:401:401:200:401:401:+++::NetWare-Enterprise-Web-Server/5.1
##200:200:200:200:200:200:---:200:200:---:---:---:200:200:200:200:200:200:200:200:200:200:200:200:+++::NetWare-Web-Manager/5.1
#
200:200:400:200:400:400:400:302:302:200:400:405:200:400:400:400:200:411:405:---:---:400:---:400:+++:^NetWare HTTP Stack:Netware Management Portal, Netware 5.1 support pack 6
# Server Version 5.6.0 September 13, 2001 -  NDS Version 10110.20 September 6, 2001
200:200:---:200:400:400:400:200:200:200:400:200:200:400:200:405:200:411:405:---:---:400:---:400:+++:^NetWare HTTP Stack:Netware Management Portal, Netware 6.0 w/o support pack
#
HTM:---:400:---:---:200:---:501:200:---:---:---:---:---:---:+++:400:404:403:403:403:403:501:501:+++::OmniHTTPd/2.10
500:200:501:200:200:200:500:200:200:500:500:500:200:302:302:302:200:404:405:405:405:405:405:405:302:^$:OMSA (Dell OpenManage Server Administrator)
500:---:501:200:---:---:500:200:---:500:500:500:---:302:302:302:200:404:405:405:405:405:405:405:302:^$:Dell OpenManage 3.6
505:200:501:505:505:505:505:200:505:505:505:505:505:200:200:200:200:200:501:501:501:501:501:501:+++:^XES 8830 WindWeb/1\.0:OkiDATA C7300dxn printer on OKI-6200e+ Print Server
# Oracle9iAS (9.0.3.0.0) Containers for J2EE
# Oracle9iAS (9.0.4.0.0) Containers for J2EE
# Oracle Application Server Containers for J2EE 10g (9.0.4.0.0)
---:200:400:200:200:---:---:400:200:---:---:---:---:400:400:+++:200:100:404:404:404:404:404:404:+++:^(Oracle9iAS|Oracle Application Server).*Containers for J2EE:Oracle AS containers for J2EE (9i or 10g)
# Oracle9iAS (9.0.2.0.0) Containers for J2EE
# Oracle9iAS (1.0.2.2.1) Containers for J2EE
---:200:400:200:200:---:---:200:200:---:400:200:---:400:400:+++:200:100:404:404:404:404:404:404:+++:^Oracle9iAS \([19]\.0\.2\.[02]\.[01]\) Containers for J2EE:Oracle9iAS Containers for J2EE
# MS-Author-Via: DAV
# Oracle XML DB/Oracle9i Enterprise Edition Release 9.2.0.1.0 - 64bit Production
# Oracle XML DB/Oracle9i Release 9.2.0.1.0 - Production
---:200:200:505:200:400:---:501:400:---:---:---:---:200:200:200:400:200:200:200:200:200:200:501:+++::Oracle XML DB/Oracle9i Release 9.2.0.1.0
# More precise. The same?!
---:200:200:505:200:400:---:501:400:---:---:---:---:200:200:200:400:200:200:200:200:200:200:501:200::Oracle XML DB/Oracle9i Enterprise Edition Release 9.2.0.1.0 - Production
# Unreliable signature: a proxy was on the way
xxx:200:200:200:200:200:xxx:200:200:200:HTM:xxx:200:400:400:+++:400:404:404:404:404:404:404:404:+++::Oracle9iAS (1.0.2.2.1) Containers for J2EE
400:200:200:200:400:400:400:200:400:400:400:400:200:200:200:200:400:+++:100:200:200:200:200:200:+++::Oracle9iAS-Web-Cache/9.0.2.0.0
400:200:501:200:400:400:400:200:400:400:400:400:200:400:400:400:400:+++:100:501:501:501:501:501:+++::Oracle9iAS-Web-Cache/9.0.2.0.0
400:200:403:200:400:400:400:501:400:400:400:400:200:200:400:400:400:+++:100:404:200:200:404:501:+++::Oracle9iAS/9.0.2 Oracle HTTP Server Oracle9iAS-Web-Cache/9.0.2.0.0 (N)

200:200:200:200:400:400:400:501:400:200:400:400:200:400:400:+++:400:404:405:404:200:200:404:501:+++::Oracle AS10g/9.0.4 Oracle HTTP Server OracleAS-Web-Cache-10g/9.0.4.0.0 (N)
# Oracle-Application-Server-10g/10.1.2.0.2 Oracle-HTTP-Server OracleAS-Web-Cache-10g/10.1.2.0.2 (G;max-age=0+0;age=0;ecid=3524385735406,0)
# Oracle-Application-Server-10g/9.0.4.0.0 Oracle-HTTP-Server OracleAS-Web-Cache-10g/9.0.4.0.0 (N)
200:200:200:200:400:400:400:501:400:200:400:400:200:200:400:400:400:404:405:404:200:200:404:501:403:^Oracle-Application-Server-10g/(9|10)\.[0-9.]+ Oracle-HTTP-Server OracleAS-Web-Cache-10g/(9|10)\.[0-9.]+:Oracle-Application-Server-10g Oracle-HTTP-Server OracleAS-Web-Cache-10g
200:200:501:200:400:400:400:200:400:200:400:400:200:400:400:+++:400:404:501:501:501:501:501:501:+++::OracleAS-Web-Cache-10g/9.0.4.0.0
# More precise
200:200:501:200:400:400:400:200:400:200:400:400:200:400:400:400:400:404:501:501:501:501:501:501:404::Oracle-Web-Cache/10g (10.1.2)
400:200:200:200:400:400:400:501:400:400:400:400:200:400:400:+++:400:100:100:404:200:200:404:501:+++::Oracle9iAS/9.0.2 Oracle HTTP Server Oracle9iAS-Web-Cache/
### More precises
# Oracle9iAS/9.0.2.3.0 Oracle HTTP Server (Unix) DAV/1.0.2 (OraDAV enabled) mod_plsql/9.0.2.6.0 mod_osso/9.0.2.0.0 mod_oc4j/3.0 mod_ossl/9.0.2.0.0 mod_fastcgi/2.2.10 mod_perl/1.26 Oracle9iAS-Web-Cache/9.0.2.3.0 (N)
# Oracle9iAS/9.0.2.3.0 Oracle HTTP Server Oracle9iAS-Web-Cache/9.0.2.3.0 (N)
400:200:200:200:400:400:400:501:400:400:400:400:200:400:400:400:400:100:100:404:200:200:404:501:200:^Oracle9iAS/9\.0\.2[0-9.]* Oracle HTTP Server.* Oracle9iAS-Web-Cache/9\.0\.2[0-9.]*:Oracle9iAS/9.0.2.3.0 Oracle HTTP Server Oracle9iAS-Web-Cache/9.0.2.3.0 (N) [unix]
400:200:200:200:400:400:400:501:400:400:400:400:200:400:400:400:400:100:100:404:200:200:404:501:403::Oracle9iAS/9.0.2.3.0 Oracle HTTP Server Oracle9iAS-Web-Cache/9.0.2.3.0 (N)
#
200:200:200:200:400:400:400:501:400:200:400:400:200:200:400:400:400:+++:405:404:200:200:404:501:+++::Oracle-Application-Server-10g/9.0.4.0.0 Oracle-HTTP-Server OracleAS-Web-Cache-10g/9.0.4.0.0 (N)
# TCP port 1830 - X-ORCL-EMSV: 4.0.1.0.0
400:200:400:400:400:400:400:200:400:400:400:400:---:200:200:400:200:+++:400:400:400:400:400:400:+++::Oracle-Application-Server-10g/9.0.4.0.0 [Oracle Net8 Cman Admin]
200:200:200:200:400:400:400:200:400:200:400:400:200:200:200:200:400:+++:200:200:200:200:200:200:+++::OracleAS-Web-Cache-10g/9.0.4.0.0
200:200:200:200:400:400:400:200:400:200:400:400:200:200:200:200:400:200:200:200:200:200:200:200:200::OracleAS-Web-Cache-10g/10.1.2.0.2
###
---:200:400:VER:---:---:---:---:---:200:---:---:200:400:400:400:200:404:400:400:400:400:400:400:414::orenosv/1.0.0
# Orion (java server) 
200:200:400:200:200:---:---:200:200:404:400:200:---:400:400:+++:+++:100:404:404:404:404:404:404:+++::Orion/2.0.1
---:200:400:200:200:---:---:501:200:---:400:200:---:400:400:400:200:100:404:404:404:404:404:404:400::Orion/1.5.2
# VMS web server
HTM:200:403:200:200:200:xxx:xxx:xxx:200:xxx:xxx:200:403:403:403:200:501:401:501:501:501:501:501:401::OSU/3.10a;UCX
HTM:200:403:200:200:200:xxx:xxx:xxx:200:xxx:xxx:200:403:403:+++:200:403:403:403:403:403:403:403:+++::OSU/3.2alpha2
HTM:200:403:200:200:200:HTM:xxx:xxx:200:xxx:HTM:200:403:403:403:200:403:403:403:403:403:403:403:501::OSU/3.9c;UCX
# More precise
HTM:200:403:200:200:200:xxx:xxx:xxx:200:xxx:xxx:200:403:403:403:200:403:403:403:403:403:403:403:200::OSU/3.6b;Multinet
HTM:200:403:200:200:200:xxx:xxx:xxx:200:xxx:xxx:200:403:403:403:200:501:501:501:501:501:501:501:200::OSU/3.3b
HTM:200:404:200:200:200:HTM:200:HTM:HTM:HTM:HTM:200:404:404:404:200:404:404:404:404:404:404:404:---::Purveyor Encrypt Export/v2.1 OpenVMS
# PlanetDNS
404:200:---:200:200:200:---:---:200:---:---:---:---:200:301:400:200:404:---:---:---:---:---:---:404:^mshweb/1\.1[0-9] NewAce Corporation:mshweb/1.1x [PlanetDNS web plugin]
#
400:200:400:200:200:200:400:200:200:400:400:400:---:400:400:+++:200:---:---:---:---:---:---:---:+++::Polycom-WS/1.0
# Used with some RAID hardware (IBM??)
400:505:501:505:404:505:400:505:505:505:400:400:505:505:505:505:404:501:501:501:501:501:501:501:505:^$:ServeRAID Manager File Server
---:200:---:200:200:200:---:200:200:---:---:---:200:---:---:---:200:+++:405:---:---:---:---:---:+++::Sipura SPA-3000 3.1.7(GWc)
# SiteCom LN-300 - single port parallel print server
HTM:200:---:200:200:200:---:---:200:200:---:---:200:---:200:200:200:---:---:---:---:---:---:---:+++:^PRINT_SERVER WEB 1\.0:SiteCom LN-300 print server
# Quicktime?
400:200:400:400:200:400:400:400:400:200:400:400:200:302:302:+++:200:404:400:400:400:400:400:400:+++::QTSS 3.0 Admin Server/1.0
# Publicfile 0.52 by DJB
HTM:404:501:404:400:400:HTM:501:400:HTM:HTM:HTM:404:404:404:404:400:501:501:501:501:501:501:501:404::publicfile [not yet configured]
HTM:200:501:200:400:400:HTM:501:400:HTM:HTM:HTM:200:404:404:404:400:501:501:501:501:501:501:501:200::publicfile
# Generic web server by WindRiver
HTM:200:200:505:400:400:400:200:400:500:400:400:200:400:400:+++:400:404:404:404:404:200:404:404:+++::Rapid Logic/1.1
---:200:501:200:200:200:---:200:200:---:---:---:---:404:404:+++:200:500:501:501:501:501:501:501:+++::RapidLogic/1.1
404:200:---:200:200:200:---:200:200:---:---:---:---:404:404:+++:200:---:---:---:---:---:---:---:+++::RapidLogic/1.1
# web server installed on a Nortel Passport-8606
---:200:501:200:200:200:---:200:200:---:---:---:---:---:---:---:200:500:501:501:501:501:501:501:---::Rapid Logic/1.1
# Raiden with PHP/4.3.10 or PHP/5.0.3
400:400:501:200:400:400:400:400:400:400:400:400:400:400:400:400:400:404:501:501:501:501:501:501:400::RaidenHTTPD/1.1.35 (Shareware)
# Resin/2.1.11 (Windows)
# Resin/2.1.10
# Resin/2.1.9 (Gentoo/Linux) - standard & EE
# Resin/2.0.4
HTM:200:HTM:200:200:HTM:---:200:200:200:---:---:200:HTM:HTM:HTM:400:404:501:501:501:501:501:501:200::Resin/2
HTM:200:HTM:200:200:HTM:---:200:200:200:---:---:200:HTM:HTM:---:400:200:405:405:405:405:501:501:200::Resin/2.1.4
HTM:500:HTM:200:500:HTM:---:500:500:500:---:---:500:HTM:HTM:HTM:400:404:501:501:501:501:501:501:500::Resin/2.1.12
xxx:302:HTM:200:302:xxx:---:302:302:302:---:---:302:xxx:xxx:xxx:400:200:501:501:501:501:501:501:302::Resin/2.1.6
HTM:200:HTM:HTM:HTM:HTM:HTM:200:400:200:HTM:HTM:200:HTM:HTM:HTM:400:---:200:200:200:200:200:200:200::Resin/3.0.5
HTM:200:HTM:HTM:200:200:HTM:200:400:200:HTM:HTM:200:HTM:HTM:---:400:404:501:501:501:501:501:501:200::Resin/3.0.6
HTM:200:HTM:HTM:400:400:HTM:200:200:200:HTM:HTM:200:HTM:HTM:---:400:404:501:501:501:501:501:501:200::Resin/3.0.6
# Very odd - I got two different signatures on a Win32 machine (the Resin/2 above and this one)
400:200:500:200:400:400:400:400:400:200:400:400:200:500:500:500:200:404:501:501:200:200:501:501:200::Resin/2.1.11
HTM:200:404:VER:400:400:HTM:400:400:HTM:HTM:HTM:200:404:302:302:400:200:405:405:404:404:404:404:200::Roxen/2.2.252
# Administration interface on port 22202
HTM:200:404:200:400:400:HTM:400:400:HTM:HTM:HTM:200:200:302:302:400:200:200:200:200:200:200:200:200::Roxen/4.0.325·NT-release4 [administration interface]
#
HTM:404:404:VER:400:400:HTM:400:400:HTM:HTM:HTM:404:404:404:404:400:404:404:404:404:404:404:404:404::Roxen/4.0.325·NT-release4 [not configured]
HTM:200:404:200:400:400:HTM:400:400:HTM:HTM:HTM:200:200:302:302:400:404:405:404:501:501:501:501:200::Roxen/4.0.325·NT-release4
#
200:200:501:200:200:200:---:404:404:---:---:200:200:200:404:404:200:400:400:501:501:501:501:501:404::SAMBAR
200:200:404:200:200:200:---:404:404:---:---:200:200:200:404:404:200:400:400:401:200:401:401:401:404::SAMBAR 5.0
# Also used by MySQL as MaxDB
200:200:404:200:400:400:400:400:400:400:400:400:---:404:404:400:400:400:400:404:404:404:404:400:404::SAP-Internet-SapDb-Server/1.0 [MaxDB]
# Savant
xxx:200:500:400:200:400:xxx:200:xxx:200:xxx:xxx:200:200:500:500:200:405:405:405:405:405:405:405:---::Savant/3.1
# sh-httpd 0.3 or 0.4 (who uses this gizmo?)
200:200:501:200:200:200:200:501:200:200:501:200:---:404:404:+++:200:501:501:501:501:501:501:501:404:ShellHTTPD/:sh-httpd
HTM:200:200:VER:400:HTM:---:200:400:200:---:---:200:200:200:200:400:200:200:200:200:200:200:200:+++::SilverStream Server/10.0
# SkunkWeb 3.4.1
# SkunkWeb 3.4b5
HTM:200:xxx:VER:VER:VER:xxx:xxx:HTM:xxx:xxx:xxx:200:404:500:500:200:200:xxx:xxx:xxx:xxx:xxx:xxx:200:^SkunkWeb 3\.4(b5|\.1):SkunkWeb 3.4b5 or 3.41
HTM:200:xxx:VER:VER:VER:xxx:xxx:HTM:xxx:xxx:xxx:200:404:500:500:200:200:xxx:xxx:xxx:xxx:xxx:xxx:---::SkunkWeb 3.4b5
200:200:400:200:200:200:400:200:200:400:400:400:200:200:200:404:200:---:400:400:400:400:400:400:+++::AnalogX SimpleServer 1.23
# Slimdevices's SlimServer 5.1
400:200:400:400:400:400:400:200:400:400:400:400:200:400:404:400:200:400:400:400:400:400:400:400:+++:^$:SlimServer 5.1
# SonicWALL, model# SOHO 3 (CPU: Toshiba 3927 H2 / 133 Mhz), running firmware v6.5.0.4.
---:200:---:200:---:---:---:---:---:---:---:---:400:200:200:---:200:+++:---:---:---:---:---:---:+++::SonicWALL [v6.5.0.4]
# ---:200:400:200:200:200:400:400:200:400:400:400:400:200:200:+++:200:404:404:400:400:400:400:400:+++::SonicWALL
# More precise
---:200:400:200:200:200:400:400:200:400:400:400:400:200:200:404:200:404:404:400:400:400:400:400:+++::SonicWALL
---:200:400:200:200:200:400:400:200:400:400:400:---:200:200:+++:200:404:404:400:400:400:400:400:+++::SonicWALL
# PRO 330 / Firmware 6.5.0.4 / ROM  6.4.0.0 / VPN Hardware Accelerator
---:200:---:200:---:---:---:---:---:---:---:---:---:200:200:---:200:---:---:---:---:---:---:---:+++::SonicWALL
200:200:200:200:200:200:200:200:200:200:200:200:200:404:404:404:200:404:200:200:200:200:200:200:200::SCO I2O Dialogue Daemon 1.0
404:200:404:200:200:200:404:200:501:400:404:200:200:404:404:404:200:404:500:500:501:501:501:501:200:^$:shttpd 1.25
# Spyglass_MicroServer/2.01FC1
# Spyglass_MicroServer/2.00FC4
HTM:200:404:200:400:HTM:HTM:200:HTM:HTM:HTM:HTM:200:404:404:+++:400:100:100:404:404:404:404:404:+++::Spyglass_MicroServer/2.0
#
400:403:400:200:400:400:400:400:400:403:400:400:403:400:400:400:403:411:411:403:200:200:400:411:403::Microsoft-IIS/5.0 thru Squid/2.5STABLE3 reverse proxy
#
---:500:500:---:---:---:---:---:---:---:---:---:500:500:500:500:500:411:404:404:404:404:404:404:500::Tcl-Webserver/3.3 March 12, 2001
---:200:500:---:---:---:---:---:---:---:---:---:200:500:500:500:200:411:404:404:404:404:404:404:200::Tcl-Webserver/3.4.2 September 3, 2002
---:200:200:---:---:---:---:---:---:---:---:---:200:200:200:200:200:411:200:200:200:200:200:200:200::Tcl-Webserver/3.5.1 May 27, 2004
# Tiny HTTPD
HTM:200:HTM:VER:VER:VER:HTM:VER:HTM:200:HTM:HTM:200:HTM:HTM:HTM:400:404:HTM:HTM:HTM:HTM:HTM:HTM:200::thttpd/2.21b 23apr2001
HTM:200:501:VER:VER:VER:xxx:VER:xxx:200:xxx:xxx:200:200:200:200:400:404:501:501:501:501:501:501:400::thttpd/2.24
HTM:200:501:HTM:HTM:HTM:HTM:200:HTM:200:HTM:HTM:200:200:200:+++:+++:404:501:501:501:501:501:501:400:^thttpd/2\.2:thttpd/2.24
HTM:200:501:HTM:HTM:HTM:400:200:HTM:200:400:400:200:400:400:+++:+++:404:501:501:501:501:501:501:200::thttpd/2.20c
HTM:200:400:VER:VER:VER:xxx:VER:xxx:200:xxx:xxx:200:400:400:400:400:404:501:501:501:501:501:501:+++::thttpd/2.25b 29dec2003
HTM:200:400:VER:VER:VER:HTM:VER:HTM:200:HTM:HTM:200:400:400:400:400:404:501:501:501:501:501:501:400::thttpd/2.25b 29dec2003
501:200:501:501:501:501:501:VER:501:501:501:501:200:501:501:501:400:404:501:501:501:501:501:501:400:^thttpd/2.25b.*:thttpd/2.25b through pound reverse proxy
HTM:400:404:200:400:HTM:HTM:400:400:HTM:HTM:HTM:400:400:400:400:400:411:404:404:404:404:404:HTM:400::tigershark/3.0
# voice-over-IP telephone
---:200:403:505:505:505:---:505:505:200:---:---:200:200:200:403:200:404:403:403:403:403:400:400:+++:^$:tiptel innovaphone 200
400:200:403:200:400:400:400:400:400:400:400:400:---:403:403:403:200:302:403:403:403:403:403:403:403:^TinyWeb/1\.9[12]:TinyWeb/1.91-92
200:200:---:200:200:200:---:200:200:---:---:---:200:HTM:HTM:+++:200:---:---:---:---:---:---:---:+++::Toaster 
# Tomcat  4.0.1 on a Sun Management Console (SMC 3.5)
##HTM:200:400:200:200:200:400:501:400:400:400:414:414:400:400:+++:+++:405:405:405:200:200:501:501:+++::Tomcat/2.1
HTM:200:400:200:200:200:400:501:400:400:400:414:414:400:400:400:200:405:405:405:200:200:501:501:+++:^Tomcat/2\.1:Apache Tomcat/2.1 [Sun Management console]
HTM:200:200:200:200:200:400:200:200:200:400:400:200:200:200:+++:200:200:200:200:200:200:200:200:+++::Apache Tomcat Web Server/3.3.1 Final
HTM:200:400:505:505:505:---:505:505:---:---:---:200:200:400:400:400:404:403:403:200:200:501:501:200:Apache Coyote/1\.0:Apache Tomcat [LiteWebServer]
---:200:400:505:505:505:---:505:505:---:---:---:200:404:400:+++:+++:404:403:403:200:200:501:501:+++:Apache Coyote/1\.0:Apache Tomcat 4.2.24
---:---:200:505:---:---:---:---:---:---:---:---:---:---:---:---:---:404:403:403:200:200:501:501:+++:Apache-Coyote/1\.1:Apache Tomcat 5.0.14 Beta
HTM:200:200:505:505:505:---:505:505:---:---:---:200:200:400:+++:400:404:403:403:200:200:501:501:+++::Apache-Coyote/1.1
XML:200:200:505:505:505:---:505:505:---:---:---:200:200:400:400:400:404:403:403:200:405:501:501:200::Apache-Coyote/1.1 [Servlet 2.4; JBoss-4.0.3RC2]
#
# product:  tamino; vendor: softwareag; os: w2k; is an xml-database. port 9991 is used by the webinterface.
HTM:200:501:200:200:HTM:HTM:HTM:HTM:HTM:HTM:HTM:---:404:404:404:200:501:501:501:501:501:501:501:+++::ARGHTTPD/2.1.1.1 [Tamino XML database web interface]
404:200:404:404:404:404:404:404:404:404:404:404:404:404:404:+++:404:404:404:404:404:404:404:404:+++::TUX/2.0 (Linux)
#
404:200:404:200:200:200:404:404:200:404:404:404:---:404:404:404:200:+++:404:404:404:404:404:404:+++::UPS_Server/1.0
# UserLand Frontier/9.0-WinNT
# UserLand Frontier/9.0.1-WinNT
400:200:404:505:200:400:400:200:200:400:400:400:---:400:400:400:400:200:404:404:404:404:404:404:200:^UserLand Frontier/9\.0(.1)?-WinNT:UserLand Frontier/9.0-WinNT
400:200:302:505:200:400:400:200:200:400:400:400:---:400:400:400:400:200:200:200:200:200:200:200:200::UserLand Frontier/9.0.1-WinNT [not configured]
# userver-0.3.0 -> userver-0.3.3
---:200:---:400:400:400:---:---:400:200:---:200:200:404:403:200:200:---:---:---:---:---:---:---:400::userver-0.3
# userver-0.4.0 -> userver-0.4.4
---:200:---:400:400:400:---:---:400:200:---:200:---:404:403:200:200:---:---:---:---:---:---:---:400::userver-0.4
# VMS
HTM:200:400:200:200:200:HTM:200:HTM:HTM:HTM:HTM:200:404:200:+++:+++:404:400:400:400:400:400:400:200::Webshare/1.2.3 VM_ESA/2.3.0.9808 CMS/14.808 REXX/4.01 CMS_Pipelines/1.0110 REXX_SOCKETS/3.01
# 
---:200:---:200:200:200:---:---:---:---:---:---:---:404:404:+++:200:---:---:---:---:---:---:---:+++::VCS-VideoJet-Webserver
---:200:---:200:200:200:---:404:---:---:---:---:---:404:404:+++:200:---:---:---:---:---:---:---:+++::VCS-VideoJet-Webserver
400:200:400:200:200:200:400:400:200:400:400:400:---:200:200:200:200:200:400:400:400:400:400:400:+++::Vertical Horizon VH-2402S
404:200:501:200:200:200:400:200:200:404:501:400:200:400:400:+++:200:404:501:501:501:501:501:501:+++::Viavideo-Web
---:200:200:200:---:---:---:200:200:---:---:---:200:403:403:403:200:403:403:405:200:200:501:501:403::VisiBroker/4.0
# VNC HTTPD (no banner!)
200:200:---:200:200:200:---:---:200:200:404:---:200:404:404:---:200:---:---:---:---:---:---:---:404:^$:VNC HTTPD (RFB 003.003)
200:200:---:200:200:200:---:---:200:---:---:---:200:404:404:+++:200:---:---:---:---:---:---:---:+++:^$:VNC HTTPD
#
400:200:501:200:200:200:400:501:200:200:400:400:200:404:404:+++:200:501:501:501:501:501:501:501:+++::RealVNC/4.0
#
404:404:501:404:404:404:404:501:404:501:501:404:404:404:404:302:404:302:501:501:501:501:501:501:404::VPOP3 Mail Http Server [2.1.0h]
# Found on a Wago Ethernet Buscoupler 750-342
# http://www.mnrcan.com/WagoHtmlFiles/Enet_Buscoupler/Wago_Enet_Buscoupler.html
404:200:501:200:200:200:400:501:200:501:501:400:200:404:404:+++:200:404:501:501:501:501:501:501:+++:^$:WAGO-I/O-System [WAGO 750-342]
#
HTM:200:400:HTM:HTM:HTM:---:200:HTM:200:---:---:200:400:400:+++:400:---:403:403:403:403:403:403:+++::WALT HTTP Server, v2.11 (22.04.03)
200:200:204:505:400:505:---:505:505:200:---:---:200:---:200:---:400:404:404:404:404:404:404:404:500:^$:Waterken/3.5
# WDaemon/6.8.4 to WDaemon/9.0.4?
400:200:501:200:200:200:400:200:200:400:400:400:---:404:404:404:200:404:501:501:501:501:501:501:404:^WDaemon/(6\.[89]|7\.[0-9]|8\.[01]|9\.0).[0-9]:WDaemon/6.8.4 to 9.0.4
200:200:404:200:200:200:404:200:200:404:404:404:---:404:404:404:200:404:404:404:404:404:404:404:400::Web Crossing/5.0
# Webfs (another gizmo?)
400:200:400:200:400:400:400:400:400:400:400:400:200:400:400:+++:+++:501:501:400:400:400:400:400:+++::webfs/1.20
400:200:405:200:400:200:405:405:400:405:405:405:200:404:404:---:---:400:400:405:405:405:405:405:+++:^Web Server/4\.10:DLink-604
# DLink Di604 firmware 1.62 (European version) - very fragile (killed by POST)
200:200:200:200:200:200:404:200:200:404:404:404:200:200:200:404:200:+++:404:404:404:404:404:404:+++:^$:DLink Di604 firmware 1.62 (European version)
# Webmin
---:200:200:200:200:200:---:200:200:200:200:200:200:200:200:+++:+++:200:200:200:200:200:200:200:200::MiniServ/0.01 [Webmin]
# SuSe Linux 8.0 Standard - Webmin 1.140 installed in https mode on port 10000
---:404:404:404:404:404:---:404:404:404:404:404:404:404:404:404:404:404:404:404:404:404:404:404:+++::MiniServ/0.01 [Webmin 1.140]
# WebLogic - note: << : >> in signature were replaced by << . >>
HTM:200:200:200:200:200:HTM:200:200:200:HTM:HTM:200:400:400:400:400:404:405:405:200:200:405:501:403::WebLogic WebLogic Server 6.1 SP4  11/08/2002 21.50.43 #221641
---:200:200:200:200:200:---:501:200:200:---:---:200:302:404:404:400:200:405:405:200:200:501:501:403::WebLogic WebLogic Server 7.0 SP2  Sun Jan 26 23.09.32 PST 2003 234192
---:200:200:200:200:200:---:200:200:200:---:---:200:200:200:404:200:200:200:200:200:200:200:200:200::WebLogic Portal 8.1 Thu Jul 10 20:09:22 PDT 2003 84868 with
400:200:200:200:200:200:---:501:200:200:---:---:200:404:302:302:400:+++:405:405:200:501:501:501:+++:^$:BEA weblogic 8.1 SP4
# D-Link
200:200:405:200:200:200:404:501:501:405:405:404:200:404:404:405:200:404:405:405:405:405:405:405:501:^$:Web Server/1.0 [might be D-Link print server]
200:200:405:200:200:200:404:501:501:405:405:404:200:404:404:405:200:+++:405:405:405:405:405:405:+++::Web Server/1.0 [D-Link DP-101P+ Print Server]
# WAS - probably not very reliable banners, as 408 = TimeOut
# 408:200:408:200:200:200:408:200:200:408:408:408:200:408:408:+++:408:200:200:200:200:200:200:200:+++::WebSphere Application Server/5.0
# More precise
408:200:408:200:200:200:408:200:200:408:408:408:200:408:408:408:408:200:200:200:200:200:200:200:+++::WebSphere Application Server/4.0
408:200:408:200:200:200:408:200:200:408:408:408:200:408:408:408:408:404:405:405:200:200:501:501:200::WebSphere Application Server/5.0 
HTM:200:HTM:200:200:200:HTM:200:200:HTM:HTM:HTM:200:HTM:HTM:HTM:400:200:200:200:200:200:200:200:200::WebSphere Application Server/4.0
# Less precise
HTM:200:HTM:200:200:200:HTM:200:200:HTM:HTM:HTM:200:HTM:HTM:HTM:400:+++:200:200:200:200:200:200:+++::WebSphere Application Server/5.1
# 4D WebStar
HTM:200:xxx:200:200:200:---:200:200:---:---:---:---:404:302:404:200:404:xxx:xxx:xxx:xxx:xxx:xxx:200::WebSTAR/3.0 ID/64110
200:200:---:200:200:200:---:---:200:---:---:---:---:404:404:404:200:---:---:---:---:---:---:---:+++::WebSTAR/4.0(SSL)
200:200:---:200:200:200:---:---:200:---:---:---:---:200:200:404:200:200:---:---:---:---:---:---:+++::WebSTAR/4.4(SSL)
# More precise
200:200:---:200:200:200:---:---:200:---:---:---:---:200:200:404:200:200:---:---:---:---:---:---:200::WebSTAR/4.3(SSL) ID/72870
200:200:---:200:200:200:---:---:200:---:---:---:---:404:404:404:200:404:---:---:---:---:---:---:404::WebSTAR/4.5(SSL)
# WebSTAR/4.5(SSL) ID/71089
# WebSTAR/4.5(SSL) ID/75942
200:200:---:200:200:200:---:---:200:---:---:---:---:404:404:404:200:404:---:---:---:---:---:---:200:^WebSTAR/4\.5\(SSL\) ID/7[1-5][0-9]{3}:WebSTAR/4.5(SSL) ID/71089-75942
# WebSTAR/4.2(SSL) ID/72840
# WebSTAR/4.5(SSL) ID/78655
200:200:405:200:200:200:---:200:200:---:---:---:---:200:200:200:200:200:405:405:405:405:405:405:200:^WebSTAR/4\.[25]\(SSL\):WebSTAR/4.2-5
200:200:200:200:200:200:---:200:200:---:---:---:---:200:200:200:200:200:200:200:200:200:---:---:200::WebSTAR/4.5(SSL) ID/72838
200:200:405:200:200:200:---:200:200:---:---:---:---:404:404:404:200:404:405:405:405:405:---:405:200::WebSTAR/4.5 Beta/1(SSL) ID/70232
#
200:200:405:200:200:200:---:200:200:---:---:---:---:404:404:404:200:404:405:405:405:405:---:---:---::WebSTAR NetCloak
200:200:404:200:200:200:---:200:200:---:---:---:---:404:404:404:200:404:404:404:404:404:xxx:xxx:200::WebSTAR NetCloak
# Lasso/6.0
---:500:200:200:---:500:---:---:---:500:---:---:500:500:500:500:500:404:405:405:200:405:405:405:500:^4D_WebSTAR_S/5\.[23]\.[0124] \(MacOS X\):4D_WebSTAR_S/5.2.4-5.3.2 (MacOS X)
---:200:200:200:---:200:---:---:---:200:---:---:200:404:404:404:200:404:405:405:200:405:405:405:200:^4D_WebSTAR_S/5\.[23]\.[1234] \(MacOS X\):4D_WebSTAR_S/5.2.3-5.3.2 (MacOS X)
---:200:200:200:---:200:---:---:---:200:---:---:200:404:404:404:200:404:401:401:401:401:401:401:200:^4D_WebSTAR_S/5\.3\.[12] \(MacOS X\):4D_WebSTAR_S/5.3.1-2 (MacOS X)
---:500:501:200:400:400:400:400:400:---:---:---:500:500:500:500:500:404:405:405:501:501:501:501:500::4D_WebSTAR_S/5.3.1 (MacOS X)
---:302:200:200:---:302:---:---:---:302:---:---:302:404:404:404:302:404:405:405:200:405:405:405:---::4D_WebSTAR_S/5.3.1 (MacOS X)
---:500:200:200:---:500:---:---:---:500:---:---:500:500:500:500:500:404:401:401:401:401:401:401:500::4D_WebSTAR_S/5.3.2 (MacOS X)
#
HTM:200:200:HTM:HTM:HTM:HTM:501:HTM:200:HTM:HTM:200:200:200:+++:400:404:501:501:404:200:501:501:+++::WN/2.2.10
# Web management from Tinix
VER:VER:302:302:VER:VER:VER:VER:VER:VER:VER:VER:VER:VER:VER:VER:VER:302:302:302:302:302:302:302:VER::Weaver/4.0b #2
# WN/2.4.6 on my Linux Gentoo box
HTM:200:200:505:505:505:HTM:501:505:200:HTM:HTM:200:200:200:400:400:200:200:200:200:200:501:501:200::WN/2.4.6 [broken conf - no index]
HTM:200:200:505:505:505:HTM:501:505:200:HTM:HTM:200:200:200:400:400:404:404:404:404:200:501:501:200::WN/2.4.6
#
200:200:404:200:200:200:200:200:200:200:200:200:200:302:302:404:200:404:404:404:404:404:404:404:404::Xeneo/2.2
200:200:501:200:200:200:400:200:200:501:501:501:---:200:200:+++:200:501:501:501:501:501:501:501:+++::XES 8830 WindWeb/1.0
HTM:200:400:200:400:HTM:HTM:---:HTM:HTM:HTM:HTM:200:400:400:+++:400:100:100:200:200:200:200:200:+++::Xerox_MicroServer/Xerox11
---:200:501:505:505:505:---:400:400:---:---:---:---:200:200:501:400:400:501:501:501:501:501:501:+++:^$:Xerox DocuColor 1632 Color Copier/Printer
---:200:---:---:---:---:---:VER:---:---:---:---:---:404:404:---:200:+++:---:---:---:---:---:---:+++:^$:Xerox Phaser 3450 DN
200:200:501:404:200:404:501:404:404:200:501:501:200:200:404:404:200:400:403:403:501:501:403:501:+++:^Xitami$:Xitami v2.4d9
200:200:501:403:200:403:501:403:403:200:501:501:200:200:404:404:200:400:403:403:501:501:403:501:200:^Xitami$:Xitami v2.4d7
# Unknow version, but <= 2.4 d9
400:200:501:501:400:501:400:400:400:400:400:400:400:200:404:404:400:400:403:403:501:501:403:501:200::Xitami
# YaWS, a web server written in Erlang; I got those banners
# Yaws/1.01 Yet Another Web Server
# Yaws/1.22 Yet Another Web Server
200:200:200:---:---:---:---:---:---:200:---:---:200:404:404:---:200:---:---:---:200:---:---:---:---:Yaws/1\.[02][12] Yet Another Web Server:Yaws/1.01 or Yaws/1.22
# New version, new behaviour...
200:200:200:---:400:400:400:400:400:200:400:400:200:404:404:---:200:---:501:501:200:501:501:501:200::Yaws/1.30 Yet Another Web Server
200:200:200:---:400:400:400:400:400:200:400:400:200:404:404:403:200:---:501:501:200:501:501:501:200::Yaws/1.31 Yet Another Web Server
# Zeroo is another gizmo which does not even implement full HTTP protocol
200:200:404:200:200:200:200:200:200:404:404:200:200:404:200:404:200:404:404:404:404:404:404:404:200:^$:Zeroo 1.5
#
HTM:404:501:400:404:400:400:501:400:404:400:400:404:400:400:400:400:404:404:501:501:501:501:501:404::Zeus/3.3
HTM:404:501:400:404:400:---:501:400:404:---:---:404:404:404:---:404:404:404:501:501:501:501:501:404::Zeus/3.3
HTM:200:501:400:200:400:400:501:400:200:400:400:200:200:200:200:400:200:200:501:501:501:501:501:200::Zeus/3.3
HTM:200:501:400:200:400:400:501:400:200:400:400:200:400:400:400:400:404:404:501:501:501:501:501:200::Zeus/3.3
HTM:200:501:400:200:400:400:501:400:200:400:400:200:400:400:400:200:404:404:501:501:501:501:501:200::Zeus/3.3
xxx:200:501:400:200:400:400:501:400:200:400:400:200:400:400:400:400:404:404:501:501:501:501:501:200::Zeus/3.3
HTM:200:400:400:200:400:400:501:400:200:400:400:200:400:400:400:400:405:405:501:501:501:501:501:200::Zeus/4.0
HTM:404:400:400:400:400:400:501:400:404:400:400:404:400:400:400:400:405:405:405:405:405:405:501:404::Zeus/4.1
HTM:403:400:400:400:400:400:501:400:403:400:400:403:400:400:400:400:405:405:405:405:405:405:501:403::Zeus/4.1
HTM:404:400:400:400:400:400:501:400:404:400:400:404:404:404:404:400:405:405:405:405:405:405:501:404::Zeus/4.2
HTM:404:400:400:400:400:500:501:400:404:500:500:404:400:400:400:404:405:405:405:405:405:405:501:404::Zeus/4.2
HTM:404:400:400:400:400:500:501:400:404:500:500:404:400:400:400:404:405:403:403:405:405:405:501:404::Zeus/4.2
HTM:404:400:400:400:400:400:501:400:404:400:400:404:400:400:400:400:405:403:403:405:405:405:501:404::Zeus/4.2
HTM:404:400:400:400:400:---:---:400:---:---:---:---:404:404:404:404:405:405:405:405:405:405:---:404::Zeus/4.2
HTM:404:400:400:400:400:500:400:400:400:500:500:404:404:404:404:404:405:405:405:405:405:405:501:404::Zeus/4.2
HTM:200:400:400:400:400:400:501:400:200:400:400:200:400:400:400:400:405:405:405:405:405:405:501:200::Zeus/4.2
HTM:200:400:400:400:400:500:501:400:200:500:500:200:400:400:400:200:405:405:501:501:501:501:501:200::Zeus/4.3
# Zeus web server from ZXTM Virtual machine 2006-02-27-1
# I don't know why the web server is identified as '4_3' and 
# the administration server as '4_4'
HTM:200:400:400:400:400:400:501:400:200:400:400:200:400:400:400:200:405:405:405:405:405:405:501:200::Zeus/4_3 [ZXTM Virtual machine 2006-02-27-1]
HTM:302:400:400:400:400:400:501:400:302:400:400:302:400:400:400:400:302:302:302:302:302:302:501:302::Zeus/4_4 [administration page]
#
HTM:200:HTM:200:200:HTM:HTM:200:HTM:400:400:HTM:200:200:301:403:400:404:HTM:HTM:HTM:HTM:HTM:HTM:200::ZazouMiniWebServer v1.0.0-rc2
# Zope/(Zope 2.5.1 (OpenBSD package zope-2.5.1p1)
# Zope/(Zope2.7.0, python 2.3.3, win32) ZServer/1.1 Plone/2.0-final
# And also Linux Gentoo, according to some old tests? I m not sure any more
500:200:404:VER:400:400:400:400:400:400:400:400:---:404:404:404:200:404:404:404:200:404:404:404:200:^Zope/\(Zope 2\.[57]\.:Zope/(Zope 2.5.1-2.7.0)
# Zope/(Zope 2.6.2 (source release, python 2.1, linux2), python 2.1.3, linux2) ZServer/1.1b1
# Zope/(Zope 2.6.1 (source release, python 2.1, linux2), python 2.1.3, linux2) ZServer/1.1b1
# Zope/(Zope 2.6.1 (binary release, python 2.1,linux2-x86), python 2.1.3, linux2) ZServer/1.1b1
# Zope/(Zope 2.5.1 (OpenBSD package zope-2.5.1p1) [yes the same server can give a different signature!]
# Zope/(Zope 2.7.4-0, python 2.3.4, linux2) ZServer/1.1
500:200:404:VER:400:400:400:400:400:400:400:400:---:404:404:404:200:404:401:404:200:404:404:404:200:^Zope/\(Zope 2\.[5-7]\.:Zope 2.5.to 2.7
500:200:404:VER:400:400:400:400:400:400:400:400:---:404:404:404:200:200:403:404:200:404:404:200:200::Zope/(Zope 2.7.0, python 2.3.4, linux2) ZServer/1.1
# Web Server/4.10 ??
400:200:405:200:400:200:405:405:400:405:405:405:200:404:404:404:400:400:400:405:405:405:405:405:400::ZyXEL-RomPager/3.02
#
400:404:501:VER:404:400:400:404:400:400:400:400:404:400:400:400:404:404:501:501:501:501:501:501:404::0W/0.6e
400:404:501:VER:404:400:400:404:400:400:400:400:404:400:400:400:404:400:501:501:501:501:501:501:404::0W/0.7e [no /]
400:200:501:VER:200:400:400:200:400:400:400:400:200:400:400:400:200:400:501:501:501:501:501:501:200::0W/0.7
#End of list";

#### Start of main code

include("http_func.inc");
include("misc_func.inc");
include("dump.inc");

port = get_http_port(default:80);
# if (! get_port_state(port)) exit(0); # Useless now

ver = int(get_kb_item("http/" + port));
no404 = get_kb_item("www/no404/" + port);

bad = 0;
debug = debug_level;

if (http_is_dead(port: port))
{
 log_print('HTTP server ', get_host_ip(), ':', port, ' is dead!\n');
 exit(0);
}

####

outdated = 0;
plugintime = cvsdate2unixtime(date: "$Date: 2006/10/10 19:52:53 $");
if (plugintime > 0)
  outdated = (unixtime() - plugintime > 86400 * 60);	# Two months

####

if (debug > 1) display("\n** Fingerprinting ", get_host_ip(), ":", port, " **\n\n");

global_var	wa;	# Reused by "no200" detection

function testreq(port, request, no404, no200)
{
  local_var	s, i, c, h, b, wansp, wa_len;
  local_var	connect_refused;

  for (j = 1; j <= 2 && !c; j ++)	# We try twice to get data
  {
    for (i = 1; i <= 3 && !s; i ++)	# We try 3*2 times to connect to the server
    {
      s = http_open_socket(port);
      if (!s)
      {
        sleep(1 + i*j);
        connect_refused ++;
      }
      else
      {
        connect_refused = 0;
      }
    }
    if (s)
    {
      send(socket: s, data: request);
      c = recv_line(socket: s, length: 1024);
      if (c)
      {
        h = http_recv_headers2(socket:s);
        b = http_recv_body(socket: s, headers: h);
      }
      http_close_socket(s); s = NULL;
    }
  }
  if (--i > 1 || --j > 1)
  {
    if (debug > 3)
     display("I=", i, "\tJ=", j, "\n");
    if (c)
     display("Problem reading data from ", get_host_ip(), ". Try to increase the timeouts\n");
   }

  if (connect_refused) exit(0);
  if (! c) return '---';

  if (h)
    wa = strcat(c, h, '\r\n', b);	# Whole answer
  else
    wa = strcat(c, b);

  i = 0;
  wa_len = strlen(wa);
  while ( i < wa_len && (wa[i] == ' ' || wa[i] == '\t' || wa[i] == '\r' || wa[i] == '\n'))
    i ++;
 
  if ( i >= wa_len ) return NULL;

  # We truncate the string, because ereg functions do not work on big strings
  wansp = substr(wa, i, i + 2048);

  # Just a try. If it breaks anything, just remove this line
  # and change back BLK to xxx in the signatures
  # if (wa =~ '^[ \t\r\n]*$') return 'BLK';
  if (wansp == '') return 'BLK';

  if (debug > 3) display("code=", c, "\n");

  if (! ereg(string: c, pattern: "^HTTP(/[0-9]\.[0-9])? +[0-9][0-9][0-9] ") &&
      c !~ "^(HTTP/NESSUS)/[0-9A-Z.]* 5[0-9][0-9] ")
  {
    if (c =~ "^HTTP/[0-9A-Z.]* ")
      return 'VER';

    if (wansp =~ '^<\\?xml')
      return 'XML';	# Maybe I should return HTM ?

    if (wansp =~ '^<[ \t\r\n]*(HTML|TITLE|HEAD|BODY|SCRIPT|X-HTML|BR|HR|P)[ \t\r\n]*>' ||
	wansp =~ '^<[ \t\r\n]*(BODY|HTML|BR|HR|BGSOUND|FRAMESET)[ \t\r\n]+[A-Z\'"=*,#0-9.:/ \t\r\n-]*>' ||
	wansp =~ '^<[ \t\r\n]*META[ \t\r\n]' ||
	wansp =~ '^<[ \t\r\n]*(A|BASE)[ \t\r\n]+HREF[ \t\r\n]*=[ \t\r\n]*"' ||
	wansp =~ '<[ \t\r\n]*(PRE|H[1-9]|P|B)[ \t\r\n]*>.*<[ \t\r\n]*/\\1[ \t\r\n]*>' ||
	wansp =~ '^<[ \t\r\n]*script +(type|language)=["\']?(text/javascript|JavaScript|jscript\\.encode)["\']?[ \t\r\n]*>?' ||
	wansp =~ '^<jsp:useBean +[A-Z"=#0-9 \t\r\n]*/>[ \t\r\n]*<[ \t\r\n]*HTML[ \t\r\n]*>' ||
	wansp =~ '^<!DOCTYPE +(HTML|doctype|PUBLIC)' ||
	wansp =~ '^<[ \t\r\n]SCRIPT +(SRC|LANGUAGE)="' ||
	wansp =~ '^<[ \t\r\n]*LINK[ \t\r\n]+rel="[a-z]+"' ||
	wansp =~ '<[ \t\r\n]*\\?php [^>]*>' ||
	wansp =~ '<[ \t\r\n]*CENTER[ \t\r\n]*>' ||
	wa =~ '<[ \t\r\n]*STYLE[ \t\r\n]+TYPE="text/css"[ \t\r\n]*>' ||
	wa =~ '<[ \t\r\n]*TABLE([ \t\r\n]+[A-Z]+=([0-9]+%?|[a-z]+))*[ \t\r\n]*>' ||
	wa =~ '<[ \t\r\n]*STYLE[ \t\r\n]*>\\.[a-z]+' ||
	wansp =~ '^<[ \t\r\n]*(BODY|HTML)[ \t\r\n]+lang="[^"]+">[ \t\r\n>]' ||
	wansp =~ '^<\\?php[ \t\r\n]' ||
	wansp =~ '<[ \t\r\n]*(PRE|H[1-9]|P|B)[ \t\r\n]*>[ \t\r\n]*<[ \t\r\n]*FONT([ \t\r\n]+SIZE="\\+?[0-9]+")?[ \t\r\n]*>' ||
	wansp =~ '<[ \t\r\n]*FRAMESET[ \t\r\n]*>' ||
	# If we get an HTML comment, there is a high probability that what 
	# comes next is HTML
	wansp =~ '^<!--.*-->')
      return 'HTM';
    else if (wa =~ '501 Method not implemented')
      return 501;
    else
    {
      if (debug > 1)
      {
        #dump(ddata: request, dtitle: "Request");
        #dump(ddata: wa, dtitle: "Answer");
        display("\n**** Request ****\n", request, "**** answer ****\n", wansp, "****\n");
      }
      return 'xxx';
    }
  }

  if (c =~ "^HTTP(/[0-9.]+)? 200" && no404 && no404 >< wa)
    return 404;
  if (c=~ "^HTTP(/[0-9.]+)? 404" && no200 && no200 >< wa)
    return 200;

  c = strstr(c, ' ');
  return int(substr(c, 1, 3));
}

function same_start(s1, s2)
{
  local_var	l, l2, i;

  l = strlen(s1);
  l2 = strlen(s2);
  if (l > l2) l = l2;

  for (i = 0; i < l; i ++)
   if (s1[i] != s2[i])
     return 0;
  return 1;
}

#### Banner

banner = get_http_banner(port: port);
if (banner)
{
  xheaders = ""; b = banner;
  while (1)
  {
    # Interesting headers: X-Powered-By, Ms-Author-Via, ETag,
    # and Via (a proxy may disturb the signature)
    xx = egrep(pattern: '^(([a-zA-Z-]*Via)|(X-[a-zA-Z-]+)|ETag):', string: b);
    if (!xx) break;
    # egrep may return a multiline result
    foreach x (split(xx)) {
      b -= x;
      x -= '\r';
      xheaders += x;
    }
  }    
  banner = egrep(pattern: '^Server:', string: banner);
}
if (debug > 0 && xheaders)
  display("Server=", banner, "\n**** X ****\n", xheaders, "***********\n");

if (banner)
{
  banner = ereg_replace(string: banner, pattern: "^Server: *(.*)$", replace: "\1");
  banner -= '\r\n';
}

#### Reference request

r = http_get(port: port, item: "/");
t = testreq(port: port, request: r, no404: no404);
no200="";

redir = NULL;
slash_is_forbidden = NULL;

if (! t)
{
  # Very unreliable!
  if (debug > 0) display("hmap: server is dead or very slow\n");
  exit(0);
}
else if (t == 'H')
{
  if (ver > 9)
  {
    display("hmap: inconsistent HTTP/0.9 answer with version ", ver, "\n");
    exit(0);
  }
  ver = 9;
}
else if (t == 301 || t == 302 || t == 303)
{
  if (debug > 0) display("hmap: / is redirected, signature may be unreliable\n");
  redir = t;
  if (debug > 1) display("redir=", redir, "\n");
  bad ++;	# Is this so bad?
}
else if (t == 404)
{
  if (debug > 0) display("hmap: / is not found, expect problems\n");
  # Try to fix
  no200 = egrep(string: wa, pattern: ".*(<h1>[^<]*</h1>).*", icase: 1);
  if (! no200)
    no200 = egrep(string: wa, pattern: ".*(<h2>[^<]*</h2>).*", icase: 1);
  if (no200)
    no200 = ereg_replace(string: no200, pattern: ".*(<h[12]>[^<]*</h[12]>).*", icase: 1, replace: "\1");
  if (no200 && debug > 1) display("no200=", no200, "\n");
  if (! no200) bad ++;
}
else if (t == 401)
{
# Note that we should not do this with 403, because it might be returned by
# some servers which "forbid" some odd requests.
  slash_is_forbidden = "401";
}
else if (t != 200)
{
  if (debug > 0)
   display("hmap: / is forbidden or in error, expect problems (code=", t, ")\n");
  bad ++;
}

last_code = t;
broken_srv = 1;

####

h = get_host_name();

reqL1 = make_list(
'GET /\r\n\r\n',				# HTTP/0.9
'GET / HTTP/1.0\r\n\r\n',			# HTTP/1.0
## Removed: always got 200
##'GET / HTTP/1.1\r\nHost: ' + h + '\r\n\r\n',	# HTTP/1.1
'OPTIONS * HTTP/1.1\r\nHost: ' + h + '\r\n\r\n',# OPTIONS *
'GET / HTTP/3.14\r\nHost: ' + h + '\r\n\r\n',	# SciFi
'GET / HTTP/1.X\r\n\r\n',			# Alphanum HTTP version
'GET / HTTP/\r\n\r\n',				# Incomplete
'GET\r\n\r\n',					# Very incomplete!
'get / http/1.0\r\n\r\n',			# Lowercase method
'GET / NESSUS/1.0\r\n\r\n',			# Unknown protocol
'GET\t/\tHTTP/1.0\r\n\r\n',			# Tab separator
'GET/HTTP/1.0\r\n\r\n',				# No separator
'GET\n/\nHTTP/1.0\r\n\r\n',			# \n instead of blank
'GET / HTTP/1.0\n\n',				# LF instead of CRLF
'GET \\ HTTP/1.0\r\n\r\n',			# Windows like URI
'GET . HTTP/1.0\r\n\r\n',			# relative URI
'HEAD .. HTTP/1.0\r\n\r\n',			# relative + forbidden
## Not added: I thought that it might help recognize Netscape/4.1 from 
## Netscape/6.0, but not always.
## 'HEAD /../ HTTP/1.0\r\n\r\n',		# forbidden
'GET / HTTP/1.1\r\n\r\n'			# Incomplete HTTP/1.1 request
);
# 17 requests

methods = make_list(
## GET & HEAD removed: always returned 404
	'POST',	# Dangerous - disabled in "safe checks" below
	'PUT', 'DELETE',
	'OPTIONS', 'TRACE',
## MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK 
## returned the same results as COPY
	'COPY', 'SEARCH'
	);

# Dangerous requests
reqL2 = make_list(
string("GET ", crap(data: "////////", length: 1024), " HTTP/1.0\r\n\r\n")
);

sign = ""; 
rawsign = "";

# Ignore safe_checks if server is supposed to be Apache
# (or anything else that is robust enough):
# 1. the server is not vulnerable to a too long request
# 2. we need such request to differentiate close versions or 
#    configurations of Apache.
no_dangerous_req = safe_checks() && (banner !~ "^((.*Powered by )?Apache|IBM_HTTP_SERVER|Oracle|Lotus-Domino|Microsoft-IIS|CompaqHTTPServer)");

# Get authorization string - we do not support complex schemes here
a = get_kb_item("/tmp/http/auth/"+port);
if (! a)
 a = get_kb_item("http/auth");

foreach r (reqL1)
{
  if (a)
    r = str_replace(find: '\n', string: r, replace: '\n'+a+'\r\n', count: 1);
  t = testreq(port: port, request: r, no404: no404, no200: no200);
  if (isnull(t)) break;
  if (t != last_code) broken_srv = 0;
  rawsign = strcat(rawsign, t, ":");
  if (t == redir || t == slash_is_forbidden) t = "200";
  sign = strcat(sign, t, ":");
}

foreach m (methods)
{
  if (no_dangerous_req && m == 'POST')
    t = '+++';
  else
  {
  if (a)
    r = str_replace(find: '\n', string: r, replace: '\n'+a+'\r\n', count: 1);
  r = http_get(item: "/" + rand_str(), port: port);
  r = ereg_replace(pattern: "^GET", replace: m, string: r);
  t = testreq(port: port, request: r, no404: no404, no200: no200);
  if (isnull(t)) break;
  }
  if (t != last_code) broken_srv = 0;
  rawsign = strcat(rawsign, t, ":");
  if (t == redir || t == slash_is_forbidden) t = "200";
  sign = strcat(sign, t, ":");
}

foreach r (reqL2)
  if (! no_dangerous_req)
  {
    t = testreq(port: port, request: r, no404: no404, no200: no200);
    if (isnull(t)) break;
    if (t != last_code) broken_srv = 0;
    rawsign = strcat(rawsign, t, ":");
    if (t == redir || t == slash_is_forbidden) t = "200";
    sign = strcat(sign, t, ":");
  }
  else
  {
    rawsign += '+++:';
    sign += '+++:';
  }

if (debug > 0) display("sign   = ", sign, "\n");
if (debug > 0 && sign != rawsign) display("rawsign= ", rawsign, "\n");

if (xheaders && debug > 0)
  display("--- xheaders ---\n", xheaders, "----------------\n");
s = egrep(string: fingerprints, pattern :  "^"+rawsign+"[^:]*:.*$");
if (!s)
s = egrep(string: fingerprints, pattern :  "^"+sign+"[^:]*:.*$");

# TBD: if Etag is present, there should be a way to match it.

if (broken_srv)
{
  exit(0);
}

#### Fuzzy match

if (!s) 
{
results = split(sign, sep: ":");	# keep: 0
rawresults = split(rawsign, sep: ':');

foreach sig (split(fingerprints))	# keep: 0
{
  if (! match(string: sig, pattern: "#*")) {
    v = split(sig, sep: ":");	# keep: 0
    n = max_index(v);
    if (n > 22)	# ?
    {
      srv = v[n-1] - '\n';
      re = v[n-2];
      diff = 0; rawdiff = 0;
      for (i = 0; i < n-2; i ++)
        if (v[i] != '+++:' && results[i] != '+++:')
        {
          if (v[i] != results[i])
            diff ++;
          if (v[i] != rawresults[i])
            rawdiff ++;
         }

      differences[srv] = diff;
      rawdifferences[srv] = rawdiff;

      if (rawdiff == 0 && !s)
      {
        #display("S=", rawsign, "\n matches: \nS=", sig, "\n");
        s = sig; 
        break;
       }
      if (diff == 0 && !s)
      {
        #display("S=", sign, "\n matches: \nS=", sig, "\n");
        s = sig; 
        break;
       }
     }
  }
}

m = 999999;
foreach d (differences) { if (d < m) m = d; }
foreach d (rawdifferences) { if (d < m) m = d; }

hyp = ""; prev = ""; nb_hyp = 0;
foreach i (keys(differences))
  if (rawdifferences[i] == m)
  {
    if (i != prev)
      hyp = string(hyp, i, "\n");
    prev = i;
    nb_hyp ++;
  }
  else if (differences[i] == m)
  {
    if (i != prev)
      hyp = string(hyp, i, "\n");
    prev = i;
    nb_hyp ++;
  }
## display("nb_hyp=", nb_hyp, "\n");
}

set_kb_item(name: "www/hmap/"+port+"/signature", value: sign);
set_kb_item(name: "www/hmap/"+port+"/raw_signature", value: rawsign);

if (http_is_dead(port: port))
security_hole(port: port, data: "HMAP killed your web server.
You should upgrade your software.

Risk: high");

if (s)
{
  r = split(s, sep: ":");
  n = max_index(r); re = r[n-2] - ":"; srv = r[n-1]; srv -= '\n';
  re = ereg_replace(string: re, pattern: "^\^Apache", 
                    replace: '^([A-Za-z_-]+(/[0-9.]+)?[ \t]+)?Apache');
  srv2 = ereg_replace(string: srv, pattern: ' +\\[[^]]+\\]$', replace: '');

  if (debug > 3) 
    display("banner=", banner, "\nRE=", re, "\nSRV=", srv, "\nSRV2=", srv2, '\n');

  if (re)
    set_kb_item(name: "www/hmap/"+port+"/banner_regex", value: re);
  if (srv)
    set_kb_item(name: "www/hmap/"+port+"/description", value: srv);

  more_info = 1;
  if (! banner)
  {
    if (re == "^$")
      rep = strcat("This web server was fingerprinted as: ", srv);
    else
      rep = strcat("Although it tries to hide its version, 
this web server was fingerprinted as: ", srv);
  }
  else if (	re && ereg(string: banner, pattern: re) ||
		! re && banner == srv2 )
  {
    rep = strcat("This web server was fingerprinted as ", srv, "
which is consistent with the displayed banner: ", banner);
    set_kb_item(name: "www/hmap/"+port+"/banner_ok", value: 1);
  }
# Apache short banners are a special case
  else if ((! re || banner =~ "^Apache(/[1-9](\.[0-9]+)?)?$") && same_start(s1: banner, s2: srv))
  {
    rep = strcat("This web server was fingerprinted as ", srv, "
This seems to be consistent with the displayed banner: ", banner);
    set_kb_item(name: "www/hmap/"+port+"/banner_ok", value: 1);
  }
  else
  {
    rep = strcat("This web server was fingerprinted as: ", srv, "
which is not consistent with the displayed banner: ", banner);
    more_info = 0;
    if (!bad)
      if (outdated)
      {
        rep = strcat(rep, '\n\nThis plugin seems out of date.\nYou should run nessus-update-plugins to get better results');
      }
      else
      {
      rep = strcat(rep, '\n\n', 
	"If you think that Nessus was wrong, please send this signature 
to www-signatures@nessus.org :
", sign + "FIXME:" + banner + '\n');
      if (xheaders)
        rep = rep + 'Including these headers:\n' + xheaders;
      rep += "
Try to provide as much information as you can: software & operating 
system release, sub-version, patch numbers, and specific configuration 
options, if any.";
      }
    set_kb_item(name: "www/hmap/"+port+"/banner_ok", value: 0);
  }

  if (! outdated)
  {
  if (sign >!< "+++" && s >< "+++")
    rep += "

You found a better signature than the already known one.
Please send this to www-signatures@nessus.org:
" + sign + '\n' + s + '\n';

  else if (report_verbosity > 9999 &&	# Disabled for the moment!
	more_info && srv =~ "^[A-Z_ -]+(/[0-9]+(\.[0-9])?)?$")
    rep += "

If you can provide more information about the server software and
operating system versions, specific configuration options, modules, 
service packs, hotfixes, patches, etc., please send them to
www-signatures@nessus.org with this signature:
" + sign + "DETAILS:" + banner + '\n';
  }

  security_note(port: port, data: rep);
  exit(0);
}

####

rep = "Nessus was not able to ";
if (bad)
  rep = string(rep, "reliably");
else
  rep = string(rep, "exactly");
rep = string(rep, " identify this server. It might be:\n", 
	hyp, "The fingerprint differs from these known signatures on ", 
	m, " point(s)\n");

# Should I store this results in the KB?

####

if (!bad)
{
  rep = rep + "
If you know what this server is and if you are using an up to date version
of this script, please send this signature to www-signatures@nessus.org :
" + sign + ":" + banner + '\n';
  if (rawsign != sign)
    rep = strcat(rep, rawsign, 'RAW:', banner, '\n');
  if (xheaders)
    rep = rep + 'Including these headers:\n' + xheaders;
 rep += "
Try to provide as much information as you can: software & operating 
system release, sub-version, patch numbers, and specific configuration 
options, if any.";
}

security_note(port: port, data: rep);
