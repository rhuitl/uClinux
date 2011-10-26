# This script was written by Michel Arboi <arboi@alussinan.org>
#
# Released under GPLv2
#
# Known top level domain wildcards, from 
# http://www.imperialviolet.org/dnsfix.html
#
# .COM and .NET	64.94.110.11 (and possibly others in AS30060)	
# .NU	64.55.105.9 212.181.91.6
# .TK	195.20.32.83 195.20.32.86
# .CC	206.253.214.102
# .MP	202.128.12.163
# .AC	194.205.62.122
# .CC	194.205.62.122 (206.253.214.102 also reported, but cannot confirm)
# .CX	219.88.106.80
# .MUSEUM	195.7.77.20
# .PH	203.119.4.6
# .SH	194.205.62.62
# .TM	194.205.62.42 (194.205.62.62 also reported, but cannot confirm)
# .WS	216.35.187.246
# 
####
#
# I also found that:
# .PW	216.98.141.250 65.125.231.178
# .PW	69.20.61.189 (new redirection)
# .TD   146.101.245.154
# 
# .IO	194.205.62.102
# .TK	217.115.203.20	62.129.131.34
#       62.129.131.38 81.29.204.106 195.20.32.104 209.172.59.193 217.119.57.19
# .TD	www.nic.td.	62.23.61.4
# .MP	202.128.12.162 66.135.225.102 (new redirection?)
# .PW	 69.20.61.189  (new redirection?)
# .CX	203.119.12.43  (new redirection?)
# .NU   62.4.64.119 69.25.75.72 212.181.91.6
# .CD	64.94.29.64
# .PH	203.167.64.64	(new redirection)
# .SH	216.117.170.115 (new)
# .ST	195.178.186.40
# .TM	216.117.170.115 (new)
# .VG	64.94.29.14
# .WS	64.70.19.33 (new)


if(description)
{
 script_id(11840);
 script_version ("$Revision: 1.6 $");
 name["english"] = "Exclude toplevel domain wildcard host";
 script_name(english:name["english"]);

 desc["english"] = "
The host you were trying to scan is blacklisted: its address is known to
be returned by a wildcard on some top level domains, or it's the nessus.org
web server.

You probably mistyped its name.

Risk factor : None";

 script_description(english:desc["english"]);

 summary["english"] = "Exclude some IPs from scan";
 script_summary(english:summary["english"]);

 script_category(ACT_SCANNER);


 script_copyright(english:"This script is Copyright (C) 2003 by Michel Arboi");
 family["english"] = "Port scanners";
 script_family(english:family["english"]);
 exit(0);
}

#
excluded["64.94.110.11"] = 1;
excluded["64.55.105.9"] = 1;
excluded["212.181.91.6"] = 1;
excluded["195.20.32.83"] = 1;
excluded["195.20.32.86"] = 1;
excluded["206.253.214.102"] = 1;
excluded["202.128.12.163"] = 1;
excluded["194.205.62.122"] = 1;
excluded["219.88.106.80"] = 1;
excluded["195.7.77.20"] = 1;
excluded["203.119.4.6"] = 1;
excluded["194.205.62.62"] = 1;
excluded["194.205.62.42"] = 1;
excluded["216.35.187.246"] = 1;
#
excluded["216.98.141.250"] = 1;
excluded["65.125.231.178"] = 1;
excluded["146.101.245.154"] = 1;
#
excluded["194.205.62.102"] = 1;
excluded["202.128.12.162"] = 1;
excluded["217.115.203.20"] = 1;
excluded["62.129.131.34"]  = 1;
excluded["62.23.61.4"] = 1;
excluded["69.20.61.189"] = 1;
excluded["203.119.12.43"] = 1;
excluded["206.241.31.20"] = 1;
excluded["206.241.31.21"] = 1;
excluded["206.241.31.22"] = 1;
excluded["206.241.31.23"] = 1;
excluded["206.241.31.24"] = 1;
excluded["206.241.31.25"] = 1;
excluded["206.241.31.26"] = 1;
excluded["206.241.31.27"] = 1;
excluded["206.241.31.28"] = 1;
excluded["66.240.11.100"] = 1;
excluded["66.240.11.101"] = 1;
excluded["66.240.11.102"] = 1;
excluded["66.240.11.103"] = 1;
excluded["66.240.11.104"] = 1;
excluded["66.240.11.105"] = 1;
excluded["66.240.11.106"] = 1;
excluded["66.240.11.107"] = 1;
excluded["66.240.11.108"] = 1;
excluded["66.240.11.109"] = 1;
excluded["66.240.11.110"] = 1;
excluded["63.105.37.100"] = 1;
excluded["63.105.37.101"] = 1;
excluded["63.105.37.102"] = 1;
excluded["63.105.37.103"] = 1;
excluded["63.105.37.104"] = 1;
excluded["63.105.37.105"] = 1;
excluded["63.105.37.106"] = 1;
excluded["63.105.37.107"] = 1;
excluded["63.105.37.108"] = 1;
excluded["63.105.37.109"] = 1;
excluded["63.105.37.110"] = 1;
#
excluded["64.94.29.64"] = 1;
excluded["66.135.225.102"] = 1;
excluded["62.4.64.119"] = 1;
excluded["69.25.75.72"] = 1;
excluded["212.181.91.6"] = 1;
excluded["203.167.64.64"] = 1;
excluded["69.20.61.189"] = 1;
excluded["216.117.170.115"] = 1;
excluded["195.178.186.40"] = 1;
excluded["62.129.131.38"] = 1;
excluded["81.29.204.106"] = 1;
excluded["195.20.32.104"] = 1;
excluded["209.172.59.193"] = 1;
excluded["217.119.57.19"] = 1;
excluded["216.117.170.115"] = 1;
excluded["64.94.29.14"] = 1;
excluded["64.70.19.33"] = 1;


target = get_host_ip();

if (excluded[target])
{
 ##display(target, " is in IP blacklist\n");
 set_kb_item(name: "Host/dead", value: TRUE);
 security_note(port: 0);
 exit(0);
}

exit(0);
# We do not test if Verisign "snubby mail rejector" is running on the
# machine, as it may be used elsewhere

soc = open_sock_tcp(25);
if (!soc) exit(0);
r = recv(socket: soc, length: 256);
if (r =~ '^220 +.*Snubby Mail Rejector')
{
  ##display(target, " looks like Verisign snubby mail server\n");
  set_kb_item(name: "Host/dead", value: TRUE);
  security_note(port: 0);
}

close(soc);
