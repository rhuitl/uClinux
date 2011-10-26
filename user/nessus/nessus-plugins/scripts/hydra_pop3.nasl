#TRUSTED 4556e41b3b6893026f1b507e5c8f2941a4f5814c0350591ef6a852f42e463a40fdba6b200b6e0e621cd25e589848f28b6d43e66dbe6bda077d8edd79f4f69a00d1342415125d408a856b6396bd6490cf9e3a307454d8416dfbc98776364cc89d33f04e25a7850b84e591227c2b9450857017cc4e377c29d43c36c935d35d411b74631dc8e6bab7ff6eee6c81fc4cc2d60cbda5c7da2f4c1c0defa257690e9878e5c525416f61f57219252806e01eeb2dfe09ec6ed4192651d1d39cee59bb383cf0600f51f251ea39cc8975aa5e806070c5cb62b1b40d544f7fb3ffff31e54d941c6ae5a3825918c41d13ab2e59e5782a94db1bd8efe3ab847f6a84f9fb307633e74f82129321d14d3ae94afb39461ef26004901ec53f967d74a2dc08a447a927b59b88531bb6d7878a24f350276800b1924f58adbb4453210ceecdd4a649d993d2357fd2c283341a15c6f227adeb3d85c40f1a7604a26f5148d1618f6c655a9b46f25fb3f4d76c31fc8e539a6b32d8cd15aece2590092c22a33a30cdf3e33550d59618596e5a4fdcb98360ffbc98aaad620325eaf20f3b3580dd0218b11183cdc47335856eabe931f2e83aa8b4a74a2c0ed8eb3eb13dd6c646737eb7f7c5ed596f13155e03a4d8256790102cce73b0e90ca39c12f34b33ee3916cf378f617c81651008c04e501584ac61c0186f664337552684190274ec402c78f32f22fa4381
#
# This script was written by Michel Arboi <arboi@alussinan.org>
#
# GPL
#

if (! defined_func("script_get_preference_file_location")) exit(0);
if (! find_in_path("hydra")) exit(0);


if(description)
{
 script_id(15881);
 script_version ("1.2");
 name["english"] = "Hydra: POP3";
 script_name(english:name["english"]);
 
 desc["english"] = "
This plugin runs Hydra to find POP3 accounts & passwords by brute force.

See the section 'plugins options' to configure it
";

 script_description(english:desc["english"]);
 
 summary["english"] = "Brute force POP3 authentication with Hydra";
 script_summary(english:summary["english"]);
 script_timeout(0);
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2004 Michel Arboi");
 script_family(english:"Brute force attacks");
 script_require_keys("Secret/hydra/logins_file", "Secret/hydra/passwords_file");
 script_require_ports("Services/pop3", 110);
 script_dependencies("hydra_options.nasl", "find_service.nes", "doublecheck_std_services.nasl");
 exit(0);
}

#
throrough = get_kb_item("global_settings/thorough_tests");
if ("yes" >!< throrough) exit(0);
logins = get_kb_item("Secret/hydra/logins_file");
passwd = get_kb_item("Secret/hydra/passwords_file");
if (logins == NULL || passwd == NULL) exit(0);

port = get_kb_item("Services/pop3");
if (! port) port = 110;
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
argv[i++] = "pop3";

report = "";
results = pread(cmd: "hydra", argv: argv, nice: 5);
foreach line (split(results))
{
  v = eregmatch(string: line, pattern: 'host:.*login: *(.*) password: *(.*)$');
  if (! isnull(v))
  {
    l = chomp(v[1]);
    p = chomp(v[2]);
    report = strcat(report, 'username: ', l, '\tpassword: ', p, '\n');
  }
}

if (report)
  security_hole(port: port, 
    data: 'Hydra was able to break the following POP3 accounts:\n' + report);
