/*
 * musicbox.c -- Front end for mp3play and mixer
 *
 * (C) Copyright 2001, Damion de Soto (damion@snapgear.com).
 * (C) Copyright 2001, SnapGear Inc (http://www.snapgear.com).
 *
 * allows the mp3play program and mixer program
 * to be controlled from the keypad
 * 6 keys -	Select = Play
 * 		Exit   = Stop
 * 		Next   = Right
 * 		Prev   = Left
 * 		Vol+   = Up
 * 		Vol-   = Down
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/termios.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include "genre.h"

#define LCD_ROWS 2
#define LCD_COLS 16
#define LCD_DEV "/dev/lcdtxt"
#define KEYPAD_DEV "/dev/keypad"
#define LCD	1
#define KEYPAD 1

#ifdef KEYPAD
#define UP 0x1
#define DOWN 0x8
#define LEFT 0x2
#define RIGHT 0x4
#define EXIT 0x10
#define SELECT 0x20
#define QUIT 0x3f
#else
#define UP 0x41
#define DOWN 0x42
#define LEFT 0x44
#define RIGHT 0x43
#define EXIT 'e'
#define SELECT 's'
#define QUIT 'q'
#endif

#define MAX_LINE 160
#define PLAYLIST_SIZE 150
#define MIXER_COMMAND "mixer"
#define KILLALL "killall"
#define MP3PLAYER "mp3play"
#define MIXER_OPT "pcm"

FILE *lcddev;
int keypad;
pid_t	mp3playpid;
char **mp3play_options;
char input = 'c';
int mp3play_option_count;
int verbose = 0;

void usage(int rc);
void next_song(int signr);
static int getstreamsize(char *song);
void mkstring(char *str, char *buf, int size);
void getmp3taginfo(char *song);
void printtitle(char *song);
int strchrcnt(char *s, char c);
void play(char *song);
void set_volume(int volume);
int exec_command(char **argv);
int setlocaltermios();
void restorelocaltermios();
void savelocaltermios();
int my_getchar(int fd);
void exit_code(void);

#ifndef KEYPAD
struct termios savetio;
int setlocaltermios();
void restorelocaltermios();
void savelocaltermios();
#endif

/****************************************************************************/

/*
 *  MP3 file TAG info. Output when in verbose mode. This structure is
 *  designed to match the in-file structure, don't change it!
 *  Nice printable strings are generated in the other vars below.
 */
struct mp3tag {
    char        tag[3];
    char        title[30];
    char        artist[30];
    char        album[30];
    char        year[4];
    char        comments[30];
    unsigned char   genre;
};

static struct mp3tag    mp3_tag;
static int      mp3_gottag;

static char     mp3_title[32];
static char     mp3_artist[32];
static char     mp3_year[8];
static char     mp3_album[32];
static char     mp3_comments[32];
static char     *mp3_genre;

/*********************************************************************/

void usage(int rc) {
	printf("usage: musicbox [-hRzZ] [-@ <playlist file>][-M \"<options to mp3play>\"]\n"
			"[-s <time>] mp3-files......\n"
			"\t\t-h            this help\n"
	        "\t\t-R            repeat tracks forever\n"
			"\t\t-z            shuffle tracks\n"
			"\t\t-Z            random tracks (implicit -R)\n"
			"\t\t-s <time>     sleep between playing tracks\n"
			"\t\t-@ <playlist> read filenames from playlist\n"
			"\t\t-v            verbose stdout output\n"
			);
	exit(rc);
}

/*********************************************************************/

void next_song(int signr) {
		input = RIGHT;
}

/****************************************************************************/
/*
 *  Get stream size (just file size).
 */
static int getstreamsize(char *song)
{
    struct stat st;
    if (stat(song, &st) < 0)
        return(0);
    return(st.st_size);
}
/****************************************************************************/

void mkstring(char *str, char *buf, int size)
{
	int i, j = 0;
	char save;
	for (i = size - 1; i >= 0; i--) {
		if (buf[i] != ' ') {
			while (buf[j] == ' ') 
					j++;
			strncpy(str, &buf[j], i - j + 1);
			str[i-j+1] = '\0';
			return;
		}
	}
}

/****************************************************************************/

/*
 *  Get TAG info from mp3 file, if it is present. No point doing a
 *  fatal exit on errors, just assume no tag info is present.
 */

void getmp3taginfo(char *song)
{
    long    pos, mp3_stream_size;
    int size, mp3_fd;


    mp3_gottag = 0;
    size = sizeof(mp3_tag);
	mp3_stream_size = getstreamsize(song);
    pos = mp3_stream_size - size;
    if (pos < 0)
        return;
	mp3_fd = open(song, O_RDONLY);
	if (mp3_fd == -1)
		return;
    if (lseek(mp3_fd, pos, SEEK_SET) < 0) {
		close(mp3_fd);
        return;
	}
    if (read(mp3_fd, &mp3_tag, size) != size) {
		close(mp3_fd);
        return;
	}
    if (strncmp(&mp3_tag.tag[0], "TAG", 3) != 0) {
		close(mp3_fd);
        return;
	}

    /* Return file pointer to start of file */
    lseek(mp3_fd, 0, SEEK_SET);
	close(mp3_fd);

    /* Construct fill NULL terminated strings */
    mkstring(&mp3_title[0], &mp3_tag.title[0], sizeof(mp3_tag.title));
    mkstring(&mp3_artist[0], &mp3_tag.artist[0], sizeof(mp3_tag.artist));
//   mkstring(&mp3_album[0], &mp3_tag.album[0], sizeof(mp3_tag.album));
//   mkstring(&mp3_year[0], &mp3_tag.year[0], sizeof(mp3_tag.year));
//   mkstring(&mp3_comments[0], &mp3_tag.comments[0], sizeof(mp3_tag.comments));
//   mp3_genre = (mp3_tag.genre >= genre_count) ? "Unknown" : genre_table[mp3_tag.genre];

    mp3_gottag = 1;
}

/****************************************************************************/

/*
 *  Print out the name on a display device if present.
 */

void printtitle(char *song)
{
    char    *name, *artist;

    if (lcddev) {
	    artist = mp3_gottag ? mp3_artist : song;
    	name = mp3_gottag ? mp3_title : "";
		fprintf(lcddev, "\f%s - %s", artist, name);
		fflush(lcddev);
    }
}
/*********************************************************************/
int strchrcnt(char *s, char c) {
int i = 0;

	while (*s) {
		if (*s == c)
			i++;
		s++;
	}
	return i;
}
/*********************************************************************/
void play(char *song) {
	char **command;
	char *kill[3];
	int i, pid;
	struct sigaction sa1;

	//setup sigchld handler
	sigemptyset(&sa1.sa_mask); //dont block any signals while this one is working
	sa1.sa_flags = 0; //restart the signal
	sa1.sa_restorer = 0;
	sa1.sa_handler = next_song;
	sigaction(SIGCHLD, &sa1, NULL);

	//kill current song
	kill[0] = KILLALL;
	kill[1] = MP3PLAYER;
	kill[2] = NULL;
	pid = exec_command(kill);
	// wait for kill command to return
	while (waitpid(pid, NULL, 0) != pid);
	usleep(10000);
	if (song) {
		// copy song to command argv
		getmp3taginfo(song);
		mp3play_options[mp3play_option_count + 1] = (char *) calloc(1, strlen(song) + 1);
		strcpy(mp3play_options[mp3play_option_count + 1], song);
		mp3play_options[mp3play_option_count + 2] = NULL;
		mp3playpid = exec_command(mp3play_options); 
		printtitle(song);
		free(mp3play_options[mp3play_option_count + 1]);
	} else {
	    if (lcddev) {
			fprintf(lcddev, "\f");
			fflush(lcddev);
		}
	}
}
/*********************************************************************/
void set_volume(int volume) {
	char *command[4];
	char *vol;
	int pid;

	command[0] = MIXER_COMMAND;
	command[1] = MIXER_OPT;
	command[2] = (char *) calloc(1, 4);
	command[3] = NULL;
	sprintf(command[2], "%d", volume);
	pid = exec_command(command);
	while (waitpid(pid, NULL, 0) != pid);
	free(command[2]);
	fprintf(lcddev, "\fVolume: %d", volume);
	fflush(lcddev);
	usleep(700000);
}
/*********************************************************************/

int main (int argc, char *argv[]) {
	char *playlist_filename;
	int shuffle = 0;
	int random_play = 0;
	int repeat = 0;
	int slptime = 0;
	FILE *playlist_file;
	char **playlist;
	char *line;
	char *ptr;
	int volume = 80;
	int balance;
	int playlist_size;
	int argnr;
	int current_song = 0;
	int songs = 0;
	int i,x,j,pid;

#ifdef LCD
	lcddev = fopen(LCD_DEV, "w");
	if (lcddev == NULL) {
		fprintf(stderr, "Open failed for %s\n", LCD_DEV);
		return -1;
	}
	fprintf(lcddev, "\f");
	fflush(lcddev);
#else
	lcddev = stdout;
#endif
	atexit(exit_code);
#ifdef KEYPAD
//	keypad = openkeypad(KEYPAD_DEV);
	keypad = open(KEYPAD_DEV, O_RDONLY);
	if (keypad == -1) {
		fprintf(stderr, "Open failed for %s\n",KEYPAD_DEV);
		return -1;
	}
#else
	keypad = 0; // assign stdinput to keypad
	savelocaltermios();
	setlocaltermios();
#endif

	playlist_filename = NULL;
	mp3play_options = NULL;
	playlist_size = PLAYLIST_SIZE;
	i = 0;
	if (argc < 2)
		usage(0);

	// process options
    while ((i = getopt(argc, argv, "?hzvZR@:M:s:")) >= 0) {
        switch (i) {
		case 'z':
			shuffle = 1;
			break;
		case 'Z':
			random_play = 1;
			break;
		case 'R':
			repeat = 1;
			break;
		case 's':
            slptime = atoi(optarg);
			break;
        case '@':
			playlist_filename = (char *) malloc(strlen(optarg) + 1);
			strcpy(playlist_filename, optarg);
            break;
        case 'M':
			line = (char *) malloc(strlen(optarg) + 1);
			strcpy(line, optarg);
			mp3play_option_count = strchrcnt(line, ' ') + 1;
			mp3play_options = (char **) calloc(mp3play_option_count + 7, sizeof(char *));
			mp3play_options[0] = MP3PLAYER;
			ptr = line;
			for (i = 1; i <= mp3play_option_count; i++) {
				mp3play_options[i] = (char *) calloc(1, strlen(line) + 1);
				ptr = strtok(ptr, " ");
				strcpy(mp3play_options[i], ptr);
				ptr = NULL;
			}
			free(line);
			break;
		case 'v':
			verbose = 1;
			break;
        case 'h':
        case '?':
			usage(0);
			break;
		}
	}
	argnr = optind;
	if (!playlist_filename)
	    if (argnr >= argc)
			usage(1);

	if (!mp3play_options) {
		mp3play_options = (char **) calloc(4, sizeof(char *));
		mp3play_options[0] = MP3PLAYER;
		mp3play_option_count = 1;
		mp3play_options[mp3play_option_count] = (char *) malloc(strlen("-l") + 1);
		strcpy(mp3play_options[mp3play_option_count], "-t");
		mp3play_option_count++;
		mp3play_options[mp3play_option_count] = (char *) malloc(strlen("0") + 1);
		strcpy(mp3play_options[mp3play_option_count], "2");
	} else {
		mp3play_option_count++;
		mp3play_options[mp3play_option_count] = (char *) malloc(strlen("-l") + 1);
		strcpy(mp3play_options[mp3play_option_count], "-l");
		mp3play_option_count++;
		mp3play_options[mp3play_option_count] = (char *) malloc(strlen("0") + 1);
		strcpy(mp3play_options[mp3play_option_count], "0");
		mp3play_option_count++;
		mp3play_options[mp3play_option_count] = (char *) malloc(strlen("-l") + 1);
		strcpy(mp3play_options[mp3play_option_count], "-t");
		mp3play_option_count++;
		mp3play_options[mp3play_option_count] = (char *) malloc(strlen("0") + 1);
		strcpy(mp3play_options[mp3play_option_count], "2");
	}

	srandom(time(NULL));
	if (playlist_filename) {
		if (verbose)
		fprintf(stdout, "Reading Playlist from file:%s\n", playlist_filename);
		playlist_file = fopen(playlist_filename, "r");
		if (playlist_file == NULL) {
			fprintf(stderr, "Open failed for playlist file:%s\n", playlist_filename);
			return -1;
		}
		playlist = (char **) calloc(playlist_size, sizeof(char *));
		line = (char *) calloc(1, MAX_LINE + 1);
		if (verbose)
		fprintf(stdout, "Playlist entries:\n");
		while(line != NULL) {
			if (songs >= playlist_size) {
				playlist_size += PLAYLIST_SIZE;
				playlist = (char **) realloc(playlist, playlist_size * sizeof(char *));
			}
			line = fgets(line, MAX_LINE, playlist_file);
			if (*line != '\0') {
				playlist[songs] = (char *) calloc(1, strlen(line) + 1);
				line = strtok(line, "\n");
				playlist[songs] = strcpy(playlist[songs], line);
				if (verbose)
				fprintf(stdout, "[%d] - %s\n",songs, playlist[songs]);
				songs++;
			}
		}
		free(line);
		songs--;
	} else {
		playlist = (char **) calloc(argc, sizeof(char *));
		for (i = 0; i < (argc - argnr) ; i++) {
			playlist[i] = (char *) malloc(strlen(argv[i + argnr]) + 1);
			playlist[i] = strcpy(playlist[i], argv[i + argnr]);
		}
		songs = i - 1;
	}

	if (shuffle) {
		if (verbose)
		fprintf(stdout, "Shuffling.....\n");
        for (x = 0; (x < 10000); x++) {
			i = ((unsigned int) random()) % songs;
			j = ((unsigned int) random()) % songs;
			line = playlist[i];
			playlist[i] = playlist[j];
            playlist[j] = line;
        }
	}
	if (verbose)
	fprintf(stdout, "Init complete - %d songs in playlist\n", songs + 1);
    


	// main menu loop
	current_song = 0;
	pid = 1;
#ifdef KEYPAD
	for (;;) {
#else
	while (input != QUIT) {
#endif
		input = my_getchar(keypad);
		while ((pid = waitpid(-1, NULL, WNOHANG)) > 0) {
			if (pid == mp3playpid) {
				if (verbose)
				fprintf(stdout, "mp3play child died\n");
			    if (lcddev) {
					fprintf(lcddev, "\f");
					fflush(lcddev);
				}
			} else {
				if (verbose)
				fprintf(stdout, "another child died\n");
			}
		}
#ifndef KEYPAD
		if (input == 0x1b) {
			input = my_getchar(keypad);
			input = my_getchar(keypad);
		}
#endif
		switch (input) {
			case UP:
				volume+=10;
				if (volume > 100) {
					volume = 100;
				} else {
					set_volume(volume);
					printtitle(playlist[current_song]);
				}
				input = 'c';
				break;
			case DOWN:
				volume-=10;
				if (volume < 0) {
					volume = 0;
					break;
				} else {
					set_volume(volume);
					printtitle(playlist[current_song]);
				}
				input = 'c';
				break;
			case RIGHT : 
				if (slptime)
					sleep(slptime);
				if (random_play) {
					current_song = ((unsigned int) random()) % songs;
					if (verbose)
					fprintf(stdout, "[Random Song] - %d\n",current_song);
				} else {
					current_song++;
					if (verbose)
					fprintf(stdout, "[Next song]\n");
				}
				if (current_song > songs) {
					if (repeat) {
						current_song = 0;
						play(playlist[current_song]);
					} else {
						current_song--;
					}
				} else
					play(playlist[current_song]);
				input = 'c';
				break;
			case SELECT :
				if (verbose)
				fprintf(stdout, "[Play]\n");
				play(playlist[current_song]);
				input = 'c';
				break;
			case LEFT :
				if (random_play) {
					current_song = ((unsigned int) random()) % songs;
					if (verbose)
					fprintf(stdout, "[Random Song] - %d\n",current_song);
				} else {
					current_song--;
					if (verbose)
					fprintf(stdout, "[Prev song]\n");
				}
				if (current_song < 0) {
					current_song = 0;
				} else
					play(playlist[current_song]);
				input = 'c';
				break;
		   	case EXIT :
				if (verbose)
				fprintf(stdout, "[Stop]\n");
				play(NULL);
				input = 'c';
				break;
			default :
				break;
		}
	}
	play(NULL);
}

/****************************************************************************/
int exec_command(char **argv) {
		int i = 0;
		int pid;

		if (verbose) {
			fprintf(stdout, "executing: ");
			for (i = 0; argv[i] != NULL; i++) {
				fprintf(stdout, "%s ",argv[i]);
			}
			fprintf(stdout, "\n");
		}

		pid = vfork();
		if(pid == 0) {
		//	close(0);
		//	close(1);
		//	close(2);
			execvp(argv[0], argv);
			_exit(0);
		}

		return pid;

}


/****************************************************************************/
#ifndef KEYPAD
int setlocaltermios()
{
    struct termios  tio;

    if (tcgetattr(1, &tio) < 0) {
        fprintf(stderr, "ERROR: ioctl(TCGETA) failed, errno=%d\n",
            errno);
        exit(1);
    }

    tio.c_iflag &= ~ICRNL;
    tio.c_lflag = 0;
    tio.c_cc[VMIN] = 1;
    tio.c_cc[VTIME] = 0;

    if (tcsetattr(1, TCSAFLUSH, &tio) < 0) {
        fprintf(stderr, "ERROR: ioctl(TCSETA) failed, errno=%d\n",
            errno);
        exit(1);
    }
    return(0);
}


/****************************************************************************/
void restorelocaltermios()
{
    if (tcsetattr(1, TCSAFLUSH, &savetio) < 0) {
        fprintf(stderr, "ERROR: ioctl(TCSETA) failed, errno=%d\n",
            errno);
        exit(0);
    }
}


/****************************************************************************/
void savelocaltermios()
{
    if (tcgetattr(1, &savetio) < 0) {
        fprintf(stderr, "ERROR: ioctl(TCGETA) failed, errno=%d\n",
            errno);
        exit(0);
    }
}
#endif

/****************************************************************************/

/*
 * my_getchar -
 *
 * gets a single char from the input fd 
 * if a timeout occurs, exits the program
 * 
 */
int my_getchar(int fd) {
        fd_set rfds;
        struct timeval timeout;
        char c;
        int r;
    pid_t pid;

again:
        if (fd < 0) {
            fprintf(stderr,"Negative File Descriptor\n");
            return EOF;
        }
        FD_ZERO(&rfds);
        FD_SET(fd, &rfds);
        timeout.tv_sec = 5;
        timeout.tv_usec = 0;

    while ((pid = wait4(-1, NULL, WNOHANG, NULL)) != 0 && (pid != -1));
        r = select(fd+1, &rfds, NULL, NULL, NULL);
        if (r == -1) {
#ifdef DEBUG
                fprintf(stderr,"Select() Error\n");
#endif
                return EOF;
        }
        if (r == 0) {
#ifdef DEBUG
                fprintf(stderr,"Timeout\n");
#endif
                return 'c'; // return invalid char
        }
        if (read(fd, &c, 1) != 1) {
#ifdef DEBUG
                fprintf(stderr,"EOF\n");
#endif
                return EOF;
        }
    /* Throw away all up events */
    if (c == 0)
        goto again;
        return c;

}

/****************************************************************************/
void exit_code(void) {
#ifndef KEYPAD
	restorelocaltermios();
#endif
#ifdef LCD
	fprintf(lcddev, "\f");
	fflush(lcddev);
#endif
	close(keypad);
	fclose(lcddev);
}
