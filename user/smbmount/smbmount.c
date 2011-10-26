/*
 *  smbmount.c
 *
 *  Copyright (C) 1995, 1996 by Paal-Kr. Engstad and Volker Lendecke
 *
 */

#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <pwd.h>
#include <grp.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/stat.h>
#include <sys/types.h>
/* #include <sys/wait.h> */  /* generates a warning here */
extern pid_t waitpid(pid_t, int *, int);
#include <sys/errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <mntent.h>

#ifdef EMBED
#include <getopt.h>
#undef NR_FILE
#endif

#include <linux/fs.h>
#include <linux/smb.h>
#include <linux/smb_mount.h>

static char *progname;


static void
str_upper(char *name)
{
	while (*name)  {
		*name = toupper(*name);
		name = name + 1;
	}
}

static void
usage(void)
{
        printf("usage: %s //server/service mount-point [options]\n", progname);
        printf("Try `%s -h' for more information\n", progname);
}

static void
help(void)
{
        printf("\n");
        printf("usage: %s //server/service mount-point [options]\n", progname);
        printf("Version %s\n"
	       "\n"
               "-p port        Port to connect to (used only for testing)\n"
               "-m max_xmit    max_xmit offered (used only for testing)\n"
               "\n"
               "-s servername  Netbios name of server\n"
               "-c clientname  Netbios name of client\n"
               "-I machinename The hostname of the machine\n"
               "-U username    Username sent to server\n"
	       "-D domain      Domain name\n"
               "-u uid         uid the mounted files get\n"
               "-g gid         gid the mounted files get\n"
               "-f mode        permission the files get (octal notation)\n"
               "-d mode        permission the dirs get (octal notation)\n"
               "-C             Don't convert password to uppercase\n"
               "-P password    Use this password\n"
               "-n             Do not use any password\n"
               "               If neither -P nor -n are given, you are\n"
               "               asked for a password.\n"
               "-h             print this help text\n"
               "\n", VERSION);
}

static int
parse_args(int argc, char *argv[], struct smb_mount_data *data,
           int *got_password, int *upcase_password,
	   char *realhost, int realhost_len)
{
        int opt;
        struct passwd *pwd;
        struct group  *grp;

        *got_password = 0;
        *upcase_password = 1;

        while ((opt = getopt (argc, argv, "Cp:s:c:U:D:u:g:f:d:m:P:nI:")) != EOF)
	{
                switch (opt)
		{
                case 'C':
                        *upcase_password = 0;
                        break;
                case 'p':
                        data->addr.sin_port = htons(atoi(optarg));
                        break;
                case 's':
                        if (strlen(optarg) > sizeof(data->server_name)-1)
			{
                                fprintf(stderr, "Server name too long: %s\n",
                                        optarg);
                                return 1;
                                break;
                        }
                        strcpy(data->server_name, optarg);
                        break;
                case 'c':
                        if (strlen(optarg) > sizeof(data->client_name)-1)
			{
                                fprintf(stderr, "Client name too long: %s\n",
                                        optarg);
                                return 1;
                        }
                        strcpy(data->client_name, optarg);
                        break;
                case 'U':
                        if (strlen(optarg) > sizeof(data->username)-1)
			{
                                fprintf(stderr, "Username too long: %s\n",
                                        optarg);
                                return 1;
                        }
                        strcpy(data->username, optarg);
                        break;
		case 'D':
#if SMB_MOUNT_VERSION < 5
			fprintf(stderr, "The kernel you compiled the smbfs "
				"utils with is not able\nto accept a domain "
				"name.\nPlease upgrade your kernel AND "
				"recompile the smbfs utils\n\n");
			return 1;
#else
			if (strlen(optarg) > sizeof(data->domain)-1)
			{
                                fprintf(stderr, "Domain name too long: %s\n",
                                        optarg);
                                return 1;
                        }
                        strcpy(data->domain, optarg);
                        break;
#endif
                case 'u':
                        if (isdigit(optarg[0]))
			{
                                data->uid = atoi(optarg);
                        }
			else
			{
                                pwd = getpwnam(optarg);
                                if (pwd == NULL)
				{
                                        fprintf(stderr, "Unknown user: %s\n",
                                                optarg);
                                        return 1;
                                }
                                data->uid = pwd->pw_uid;
                        }
                        break;
                case 'g':
                        if (isdigit(optarg[0]))
			{
                                data->gid = atoi(optarg);
                        }
			else
			{
                                grp = getgrnam(optarg);
                                if (grp == NULL)
				{
                                        fprintf(stderr, "Unknown group: %s\n",
                                                optarg);
                                        return 1;
                                }
                                data->gid = grp->gr_gid;
                        }
                        break;
                case 'f':
                        data->file_mode = strtol(optarg, NULL, 8);
                        break;
                case 'd':
                        data->dir_mode = strtol(optarg, NULL, 8);
                        break;
                case 'm':
                        data->max_xmit = atoi(optarg);
                        break;
                case 'P':
			if (strlen(optarg) > sizeof(data->password)-1)
			{
				fprintf(stderr, "Password too long\n");
				return 1;
			}
                        strcpy(data->password, optarg);
                        *got_password = 1;
                        break;
                case 'n':
                        *got_password = 1;
                        break;
                case 'I':
			if (strlen(optarg) > realhost_len-1)
			{
				fprintf(stderr, "Hostname too long: %s\n",
					optarg);
				return 1;
			}
                        strcpy(realhost, optarg);
                        break;
                default:
                        return -1;
                }
        }
        return 0;
        
}

static int
extract_service(const char *service, char **server, char **share, char **root,
                char **user)
{
        char service_copy[strlen(service)+1];
        char *complete_service;

        char *share_start;
        char *root_start;
        char *user_start;

        static char s_server[64];
        static char s_share [64];
        static char s_root  [64];
        static char s_user  [64];

        strcpy(service_copy, service);
        complete_service = service_copy;

        if (strlen(complete_service) < 4) {
                return -1;
        }

        if (complete_service[0] != '/') {
                return -1;
        }

        while (complete_service[0] == '/') complete_service += 1;

        share_start = strchr(complete_service, '/');

        if (share_start == NULL) {
                return -1;
        }

        share_start[0] = '\0';
        share_start += 1;

        root_start = strchr(share_start, '/');

        if (root_start != NULL) {
                root_start[0] = '\0';
                root_start += 1;
        }

        if (   (strlen(complete_service) > 63)
            || (strlen(share_start) > 63)) {
                fprintf(stderr, "server or share too long: %s\n",
                        service);
                return -1;
        }

        if (root_start != NULL) {

                int i;

                if (strlen(root_start) > sizeof(s_root)-2) {
                        fprintf(stderr, "root too long: %s\n", root_start);
                        return -1;
                }

                s_root[0] = '/';
                strcpy(s_root+1, root_start);

                for (i = 0; s_root[i] != '\0'; i++) {
                        if (s_root[i] == '/') {
                                s_root[i] = '\\';
                        }
                }

                /* i == strlen(s_root) */
                if (s_root[i-1] == '\\') {
                        s_root[i-1] = '\0';
                }
        } else {
                s_root[0] = '\0';
        }

        user_start = strchr(share_start, '%');

        if (user_start != NULL) {
		if (strlen(user_start+1) > sizeof(s_user)-1)
		{
			fprintf(stderr, "user too long: %s\n", user_start+1);
			return -1;
		}

                user_start[0] = '\0';
                user_start += 1;
                strcpy(s_user, user_start);
        } else {
                s_user[0] = '\0';
        }

	/* The length of these has already been checked */
        strcpy(s_server, complete_service);
        strcpy(s_share,  share_start);

        *server = s_server;
        *share  = s_share;
        *root   = s_root;
        *user   = s_user;
        return 0;
}

static char *
fullpath(const char *p)
{
        char path[MAXPATHLEN];

	if (strlen(p) > MAXPATHLEN-1)
	{
		return NULL;
	}

#ifdef EMBED
        return strdup(p);
#else
        if (realpath(p, path) == NULL)
	{
                return strdup(p);
	}
	return strdup(path);
#endif
}

#ifndef EMBED
#ifndef HAVE_KERNELD

/* Returns 0 if the filesystem is in the kernel after this routine
   completes */
static int
load_smbfs(void)
{
	FILE *ffs;
	char s[1024];
	char *p, *p1;
        pid_t pid;
        int status;

	/* Check if smbfs is in the kernel */
	ffs = fopen("/proc/filesystems", "r");

	if (ffs == NULL)
	{
		perror("Error: \"/proc/filesystems\" could not be read");
		return -1;
	}

	p = NULL;
	while (! feof(ffs))
	{
		p1 = fgets(s, sizeof(s), ffs);
		if (p1)
		{
			p = strstr(s, "smbfs");
			if (p)
			{
				break;
			}
		}
	}
	fclose(ffs);

	if (p)
	{
		return 0;
	}

        /* system() function without signal handling, from Stevens */

        if ((pid = fork()) < 0)
	{
                return 1;
        }
	else if (pid == 0)
	{
                /* child */
                execl("/sbin/modprobe", "modprobe", "smbfs", NULL);
                _exit(127);     /* execl error */
        }
	else
	{
                /* parent */
                while (waitpid(pid, &status, 0) < 0)
		{
                        if (errno != EINTR)
			{
                                status = -1;
                                break;
                        }
                }
        }
        return status;
}

#endif /* HAVE_KERNELD */
#endif /* EMBED */

/* Check whether user is allowed to mount on the specified mount point */
static int
mount_ok(struct stat *st)
{
        if (!S_ISDIR(st->st_mode))
        {
                errno = ENOTDIR;
                return -1;
        }
	
        if (   (getuid() != 0)
            && (   (getuid() != st->st_uid)
                || ((st->st_mode & S_IRWXU) != S_IRWXU)))
        {
                errno = EPERM;
                return -1;
        }

        return 0;
}

int 
main(int argc, char *argv[])
{
        struct smb_mount_data data;
        struct stat st;

        int fd;
        int Got_Password;
        int Upcase_Password;
        int um;
	unsigned int flags;
	char hostname[MAXHOSTNAMELEN + 1];
	char realhost[MAXHOSTNAMELEN + 1];

	struct hostent *h;
        char *server;
        char *share;
        char *root;
        char *user;

        char *service;
        char *mount_point;

        struct mntent ment;
        FILE *mtab;

        progname = argv[0];

	memset(&data, 0, sizeof(struct smb_mount_data));

	memset(hostname, '\0', MAXHOSTNAMELEN+1);
	gethostname(hostname, MAXHOSTNAMELEN);

        if (argc < 3) {
                if (   (argc == 2)
                    && (argv[1][0] == '-')
                    && (argv[1][1] == 'h')
                    && (argv[1][2] == '\0')) {

                        help();
                        return 0;
                }
                else
                {
                        usage();
                        return -1;
                }
        }

        if (geteuid() != 0) {
                fprintf(stderr, "%s must be installed suid root\n", progname);
                exit(1);
        }

        service = argv[1];
        mount_point = argv[2];

        argv += 2;
        argc -= 2;

        if (extract_service(service, &server, &share, &root, &user) != 0) {
                usage();
                return -1;
        }

        if (stat(mount_point, &st) == -1) {
                fprintf(stderr, "could not find mount point %s: %s\n",
                        mount_point, strerror(errno));
                exit(1);
        }

        if (mount_ok(&st) != 0) {
                fprintf(stderr, "cannot mount on %s: %s\n",
                        mount_point, strerror(errno));
                exit(1);
        }

#ifndef EMBED
#ifndef HAVE_KERNELD
	/* Check if the smbfs filesystem is in the kernel.  If not, attempt
	 * to load the smbfs module */
	if (load_smbfs() != 0) {
		fprintf(stderr, "Error: Unable to start smbfs, exiting...\n");
		exit(1);
	}
#endif
#endif

	data.version = SMB_MOUNT_VERSION;

        /* getuid() gives us the real uid, who may umount the fs */
        data.mounted_uid = getuid();

	sprintf(data.service, "\\\\%s\\%s", server, share);
        str_upper(data.service);

        strcpy(data.root_path, root);

        if (getenv("USER")) {
                strcpy(data.username, getenv("USER"));
                str_upper(data.username);
        }

        if (data.username[0] == 0 && getenv("LOGNAME"))
        {
                strcpy(data.username,getenv("LOGNAME"));
                str_upper(data.username);
        }

        data.max_xmit = 4070;   /* allocate at most one page in kernel */
        data.uid = getuid();
        data.gid = getgid();
        um = umask(0);
        umask(um);
        data.file_mode = (S_IRWXU|S_IRWXG|S_IRWXO) & ~um;
        data.dir_mode  = 0;
	data.addr.sin_family = AF_INET;
	data.addr.sin_port = htons(SMB_PORT);

	strcpy(data.domain, "?");

        realhost[0] = '\0';

        if (parse_args(argc, argv, &data, &Got_Password,
                       &Upcase_Password, realhost, sizeof(realhost)) != 0) {
                usage();
                return -1;
        }

        if (realhost[0] == '\0') {
		if ((h = gethostbyname(server)) == NULL) {
			printf("%s: unknown host\n", server);
			printf("\tThe -I option may be useful.\n");
			return 0;
		}
        	data.addr.sin_addr.s_addr =
			((struct in_addr *)(h->h_addr))->s_addr;
	}
	else {
		if (! inet_aton(realhost, &data.addr.sin_addr)) {
			if ((h = gethostbyname(realhost)) == NULL) {
				printf("%s: unknown host\n", realhost);
				return 0;
			}
        		data.addr.sin_addr.s_addr =
				((struct in_addr *)(h->h_addr))->s_addr;
		}
	}
	
	
	data.fd = socket(AF_INET, SOCK_STREAM, 0);
	if (data.fd == -1) {
		perror("socket");
                return -1;
	}
	

        if (data.dir_mode == 0) {
                data.dir_mode = data.file_mode;
                if ((data.dir_mode & S_IRUSR) != 0)
                        data.dir_mode |= S_IXUSR;
                if ((data.dir_mode & S_IRGRP) != 0)
                        data.dir_mode |= S_IXGRP;
                if ((data.dir_mode & S_IROTH) != 0)
                        data.dir_mode |= S_IXOTH;
        }

        if (Got_Password == 0) {
#ifdef EMBED
		printf("smbmount: no getpass()\n");
		exit(1);
#else
		char *pw = getpass("Password: ");
		if (strlen(pw) > sizeof(data.password)-1)
		{
			fprintf(stderr, "Password too long\n");
			return -1;
		}
                strcpy(data.password, pw);
#endif
        }

        if (Upcase_Password == 1)
	{
                str_upper(data.password);
        }

        if (data.server_name[0] == '\0')
	{
                if (strlen(server) > sizeof(data.server_name)-1)
		{
                        fprintf(stderr, "server name too long as a netbios "
                                "name: %s\n", server);
                        fprintf(stderr, "use option -s server_name\n");
                        return -1;
                }
                strcpy(data.server_name, server);
                str_upper(data.server_name);
        }

        
        if (data.client_name[0] == '\0')
	{
                if (strlen(hostname) > sizeof(data.client_name)-1)
		{
                        fprintf(stderr, "my hostname name too long as a "
                                "netbios name: %s\n", hostname);
                        fprintf(stderr, "use option -c client_name\n");
                        return -1;
                }
                strcpy(data.client_name, hostname);
                str_upper(data.client_name);
        }
   
	flags = MS_MGC_VAL;

	if (mount(NULL, mount_point, "smbfs",
                  flags, (char *)&data) < 0) {
		perror("mount error");
	        close(data.fd);
		printf("Please look at smbmount's manual page for "
		       "possible reasons\n");
		return -1;
	}

        close(data.fd);

        ment.mnt_fsname = service;
        ment.mnt_dir = fullpath(mount_point);
        ment.mnt_type = "smbfs";
        ment.mnt_opts = "";
        ment.mnt_freq = 0;
        ment.mnt_passno= 0;

        mount_point = ment.mnt_dir;

	if (mount_point == NULL)
	{
		fprintf(stderr, "Mount point too long\n");
		return -1;
	}
	
#ifdef EMBED
	/*printf("smbmount: not updating mnttab\n");*/
#else
        if ((fd = open(MOUNTED"~", O_RDWR|O_CREAT|O_EXCL, 0600)) == -1)
        {
                fprintf(stderr, "Can't get "MOUNTED"~ lock file");
                return 1;
        }
        close(fd);
	
        if ((mtab = setmntent(MOUNTED, "a+")) == NULL)
        {
                fprintf(stderr, "Can't open " MOUNTED);
                return 1;
        }

        if (addmntent(mtab, &ment) == 1)
        {
                fprintf(stderr, "Can't write mount entry");
                return 1;
        }
        if (fchmod(fileno(mtab), 0644) == -1)
        {
                fprintf(stderr, "Can't set perms on "MOUNTED);
                return 1;
        }
        endmntent(mtab);

        if (unlink(MOUNTED"~") == -1)
        {
                fprintf(stderr, "Can't remove "MOUNTED"~");
                return 1;
        }
#endif

	return 0;
}	
