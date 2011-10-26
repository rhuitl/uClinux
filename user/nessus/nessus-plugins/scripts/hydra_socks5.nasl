#TRUSTED 8173e4b76ea29069e90a67c164ed4a70bc6d4fde86632e791dbf13f90eb741eb2bf0a4f88e5c32fb03c33dc78df883d1b444b8343e1250c470da123077d1fad17fddb06fc6dc23e271425c6db4a55613eb30c54835660db249e619c32284f467939499684a81904e0c13ecb516e280bbde0a1efcdddc3b23e9f8a907970c7e06f8489c82abdee65b183b7e68a2955d54a57693eebc61fe6051b50c3a80a554fe6a1f270b10130126726c7d94c89a120fc3839c49e21ae2ced40d1da297ab71ef93997fa477f72200182ad1c210040827b620d094964e75ac9f0c6aecb1c1417e31e890964f0a085a4ad7f6b2780ebfffc1eb75104431520f36c3ff2958a7b8d64f01b383b7b2297904146dcae7a03d5d5faa72441fc411353aea97f57692b7668fd95ae558aa0771e15b909565ba675e4c5eb1398d9ac4b9b4fac5b7d0e4c0491b143c1553d507291b066b5a3a5c5cca335a85d206936606733d877a7bb3e0f404623acb7575428c2465a8bce71118047e82a3325dfdd5d9bcdeda7b4cb2ded37b76c3837afbd21bc6262f092b53d40e2cd443f02305838813151fb9dd1f60095740ae2437f3d933ad196215949cfd734464d22627134a59cd8f58e852e37bd3f8c0e3b0d941053ccf7f7371b2b047719ecf92edd9d386a57efa3067cb0b5f0feb7750515eec4bde83fcd0fc549fed5ee91e1f710a44eca442effc96c9e14347
#
# This script was written by Michel Arboi <arboi@alussinan.org>
#
# GPL
#

# No use to run this one if the other plugins cannot run!
if ( ! defined_func("script_get_preference_file_location")) exit(0);
if ( ! find_in_path("hydra") ) exit(0);


if(description)
{
 script_id(15887);
 script_version ("1.2");
 name["english"] = "Hydra: Socks5";
 script_name(english:name["english"]);
 
 desc["english"] = "
This plugin runs Hydra to find Socks5 accounts & passwords by brute force.

See the section 'plugins options' to configure it
";

 script_description(english:desc["english"]);
 
 summary["english"] = "Brute force Socks5 authentication with Hydra";
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 script_timeout(0);
 script_copyright(english:"This script is Copyright (C) 2004 Michel Arboi");
 script_family(english:"Brute force attacks");
 script_require_keys("Secret/hydra/logins_file", "Secret/hydra/passwords_file");
 script_require_ports("Services/socks5", 1080);
 script_dependencies("hydra_options.nasl", "find_service.nes", "socks.nasl");
 exit(0);
}

#

throrough = get_kb_item("global_settings/thorough_tests");
if ("yes" >!< throrough) exit(0);
logins = get_kb_item("Secret/hydra/logins_file");
passwd = get_kb_item("Secret/hydra/passwords_file");
if (logins == NULL || passwd == NULL) exit(0);

port = get_kb_item("Services/socks5");
if (! port) port = 1080;
if (! get_port_state(port)) exit(0);

timeout = get_kb_item("/tmp/hydra/timeout"); timeout = int(timeout);
tasks = get_kb_item("/tmp/hydra/tasks"); task = int(tasks);

empty = get_kb_item("/tmp/hydra/empty_password");
login_pass = get_kb_item("/tmp/hydra/login_password");
exit_asap = get_kb_item("/tmp/hydra/exit_ASAP");
tr = get_kb_item("Transports/TCP/"+port);

i = 0;
argv[i++] = "hydra";
argv[i++] = "-s"; argv[i++] = port;
argv[i++] = "-L"; argv[i++] = logins;
argv[i++] = "-P"; argv[i++] = passwd;
s = "";
if (empty) s = "n";
if (login_pass) s+= "s";
if (s)
{
  argv[i++] = "-e"; argv[i++] = s;
}
if (exit_asap) argv[i++] = "-f";
if (tr >= ENCAPS_SSLv2) argv[i++] = "-S";

if (timeout > 0)
{
  argv[i++] = "-w";
  argv[i++] = timeout;
}
if (tasks > 0)
{
  argv[i++] = "-t";
  argv[i++] = tasks;
}

argv[i++] = get_host_ip();
argv[i++] = "socks5";

report = "";
results = pread(cmd: "hydra", argv: argv, nice: 5);
foreach line (split(results))
{
  v = eregmatch(string: line, pattern: 'host:.*login: *(.*) password: *(.*)$');
  if (! isnull(v))
  {
    l = chomp(v[1]);
    p = chomp(v[2]);
    report = strcat(report, 'login: ', l, '\tpassword: ', p, '\n');
    set_kb_item(name: 'Hydra/socks5/'+port, value: l + '\t' + p);
  }
}

if (report)
  security_hole(port: port, 
    data: 'Hydra was able to break the following accounts on the Socks5 server:\n' + report);
