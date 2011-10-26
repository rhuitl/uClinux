/****************************************************************************/
/*
 *	Coldfire Palm-bot, davidm@lineo.com
 *
 *	Based on: Part of Robot1 project
 *            Modified by Greg Reshko 1/19/2000.
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <termios.h>
#include <memory.h>
#include <math.h>
#include <syslog.h>
#include <string.h>
#include <sys/ioctl.h>
#include <linux/ledman.h>

/****************************************************************************/

static int	serial_fd = -1;
static int	ir_fd = -1;

/****************************************************************************/

#define Forward 3
#define Stop 5

#define True 1
#define False 0

#define Fast 1
#define Slow 2
#define Left      1 
#define Right     2
#define ToServo1  1
#define ToServo2  2
#define ToServo3  3
#define RToServo1 14
#define RToServo2 15
#define RToServo3 16

// vecmath.h
// Vector class and math operations for physics programs.
// by Greg Reshko
// 12/06/1999

double const PI = 3.14159265359;

class vector {
	public:
	double x, y;
	vector() {x=0; y=0;}									// vector A
	vector(double tempx, double tempy) {	// vector A(x,y)
		x=tempx; y=tempy; }
	vector operator+(vector a) {					// A = B + C
		x += a.x; y += a.y;
		return *this; }
	vector operator-(vector a) {					// A = B - C
		x -= a.x; y -= a.y;
		return *this; }
	vector operator*(double k) {					// A = B * k
		x *= k; y *= k;
		return *this; }
	double operator*(vector a) {					// k = B * C (dot product)
		return (x*a.x + y*a.y); }
	double Norm(void) {
		return (sqrt(x*x+y*y));	}
	void Set(double tempx, double tempy) {	// A.Set(x,y)
		x=tempx; y=tempy; }
};


/****************************************************************************/
__BEGIN_DECLS

extern int execl(const char *path, const char *arg0, ...);
extern void _exit(int status);
extern int sscanf(const char *str, const char *fmt, ...);

__END_DECLS
/****************************************************************************/

void Drive(int sv1, int sv2, int sv3);
void Servo(int number, int speed);
int  Sensor(int number);
int  Sensor_To_Range(int x);
void Display(int number);
void DisplayTxt(const char * str);
void DisplayIR(int sensor, int value);

void SpinAlgorithm(void);
void WallFollowAlgorithm(void);
void TravelerAlgorithm(void);
void PenFollowAlgorithm(void);

void Turn(int direction, int speed);
void Move(int direction);
void PMove(int direction);
void Wait(int delay_ticks);
void StopRobot(void);
int  Vel_To_Value(double vel);
void Vector_Drive(vector V, double omega);
int  SmartWait(int delay_ticks);

/****************************************************************************/

void
Servo(int servo, int value)
{
	char	buf[12];

	sprintf(buf, "SV%d M%d\r", servo % 10, value % 256);
	write(serial_fd, buf, strlen(buf));
}

/****************************************************************************/

int
Sensor(int sensor)
{
	char	buf[12];
	int		n;
	fd_set	rfds;
	struct timeval tv;

	tv.tv_sec = 0;
	tv.tv_usec = 0;

	FD_ZERO(&rfds);
	FD_SET(serial_fd, &rfds);

	while (select(serial_fd + 1, &rfds, 0, 0, &tv) > 0)
		if (read(serial_fd, buf, sizeof(buf)) <= 0)
			break;
	sprintf(buf, "AD%d\r", sensor % 10);
	if (write(serial_fd, buf, strlen(buf)) != strlen(buf))
		return(-1);
	
	for (n = 0; n < sizeof(buf); n++) {
		if (read(serial_fd, &buf[n], 1) != 1)
			return(-1);
		if (buf[n] == '\r')
			break;
	}
	buf[sizeof(buf) - 1] = '\0';
	return(atoi(buf));
}

/****************************************************************************/

void
simple_test(void)
{
	int s1, s2, s3;

	Drive(0, 0, 0); /* Motors off */

	printf("Read sensors\n");
	while (1) {
		s1 = Sensor(1);
		s2 = Sensor(2);
		s3 = Sensor(3);
		printf("1=%d(%d) 2=%d(%d) 3=%d(%d)\n",
				s1, Sensor_To_Range(s1),
				s2, Sensor_To_Range(s2),
				s3, Sensor_To_Range(s3));
		sleep(1);
	}
}

/****************************************************************************/
// ************* ROBOT'S FUNCTIONS *************
// ***** ALGORITHM FUNCTIONS *****

// This algorithm locks onto target and follows it.
// The robot adjusts its position and orientation so that
// sensor #3 always faces the target from 25...35cm distance.
// For faster target location, put target next to wheel #1.
// All objects further than 70cm are ignored.

void PenFollowAlgorithm(void) {
	unsigned long start_time;
	int pen_dist=30, dist, detected = False, lost = False, infi = 60, played = False;
	// put pen facing wheel #1
	// turn robot to the right until it finds the center of the pen
	Turn(Right, Slow);
	DisplayTxt("Scanning...");
	do {
		dist = Sensor_To_Range(Sensor(3));
		if (dist <= pen_dist) 
			detected = True;
	} while ( (detected == False) && (SmartWait(1)==0) );
	StopRobot();	// stop robot
	// begin tracking loop
	do {
		// ADJUST ANGULAR POSITION
		dist = Sensor_To_Range(Sensor(3));
		if (dist > infi) {	// target lost turn left/right
			played = False;
			Turn(Right,Slow); Wait(50); StopRobot(); // turn right for awhile
			dist = Sensor_To_Range(Sensor(3));	
			if (dist > infi) { // target is not to the right,
				Turn(Left,Slow);// turn left
				start_time = 0;
				do { 
					dist = Sensor_To_Range(Sensor(3));
				} while ((start_time++ < 1000) && (dist > infi) && (SmartWait(1)==0) );	// turn until found
				dist = Sensor_To_Range(Sensor(3));
				if (dist > infi) {
					lost = True;
					break; }
				StopRobot(); } }
		dist = Sensor_To_Range(Sensor(3));		
		// ADJUST LINEAR POSITION
		if ( (dist < infi) && (dist < (pen_dist-5)) )	{ // too close to target
			played = False;
			Move(RToServo3);
			do {
				dist = Sensor_To_Range(Sensor(3));
				if (dist > infi) 	// lost angular tracking
					break;
			} while (dist < pen_dist);	// get dist to pen_dist
			StopRobot(); }
		if ( (dist < infi) && (dist > (pen_dist+5)) )	{ // too far 
			played = False;
			Move(ToServo3);
			do {
				dist = Sensor_To_Range(Sensor(3));
				if (dist > infi)	// lost angular tracking
					break;
			} while (dist > pen_dist);	// get dist to pen_dist
			StopRobot(); }
		if ( (dist < (pen_dist+5)) && (dist > (pen_dist-5)) && (played == False) ) {
			printf("Yep\n");												
			played = True; }
	} while ( (lost == False) && (SmartWait(10)==0) );
	StopRobot();
}

/****************************************************************************/

// "DRIVE & SPIN" SmartAlgorithm
// Robot moves forward while continously rotating.
// The loop is infinite and can be interrupted by penDown event
// at any time.

void SpinAlgorithm(void) {
	vector V(0,0);
	double omega=0.20, h=0;			// body angular velocity in rad/sec
	do {	
		V.x = 	0.07*cos(h);		// body x velocity vector in meters
		V.y = 	0.07*sin(h);		// body y velocity vector in meters
		h += omega;					// turn velocity vector by omega
		Vector_Drive(V, omega);		// drive robot using direction vector and angular velocity
	}	while (SmartWait(90) == 0); // loop will be interrupted by penDown event
	StopRobot();
}

/****************************************************************************/
// "WALL FOLLOW 2" SmartAlgorithm
// The robot follows a wall facing it with wheel #3 and
// using IR sensors #1 and #2.

void WallFollowAlgorithm(void) {
	vector Z(0,0);
	int dist1, dist2, dist, Tdist1=50, Tdist2=50;
	int t=5;	// tolerance
	Drive(136,136,50);						// initially drive straight
	while ( SmartWait(2)==0 ) {
		dist1 = Sensor_To_Range(Sensor(1));
		dist2 = Sensor_To_Range(Sensor(2));		
		if (dist1 > (dist2+t))	
			Drive(136-4,136-4,50); 		// dist1 > dist2 -> turn left
		else 
			if (dist1 < (dist2-t))	
				Drive(136+5,136+5,50);	//	dist2 > dist1 -> turn right
			else
				if ( (dist1 > (Tdist1+t/2)) && (dist2 > (Tdist2+t/2)) ) // too far
					// dist1 > Tdist1 and dist2 > Tdist2 -> move close
					Drive(136+5,136-4,50);
				else
					if ( (dist1 < (Tdist1-t/2)) && (dist2 < (Tdist2-t/2)) ) // too close
						// dist1 < Tdist1 and dist2 < Tdist2 -> move far
						Drive(136-4,136+5,50);
					else
						Drive(136,136,50); }	// Drive straight
	StopRobot();
}

/****************************************************************************/

void TravelerAlgorithm(void)
{
	vector Z(0,0);
	double omega, vel=0.07;	// vel is top speed of servos
	int chosen_dir = 1, quit_loop=0;
	int sensor[6], sensor_obstacle=30, sensor_clearview=40;
	Move(chosen_dir);
	do {
		do { 		// drive until robot sees an obstacle using a current sensor
			quit_loop = SmartWait(1);  	// obstacle detected
		} while ( (Sensor_To_Range(Sensor(chosen_dir)) > sensor_obstacle) && (quit_loop == 0) && (chosen_dir!=0) );
		sensor[1] = Sensor_To_Range(Sensor(1));	// get sensors
		sensor[2] = Sensor_To_Range(Sensor(2));
		sensor[3] = Sensor_To_Range(Sensor(3));		
		sensor[4] = sensor[1];		
		sensor[5] = sensor[2];		
		// sensor+1 -> obstalce & sensor+2 -> obstalce
		if ( (sensor[chosen_dir+2] < sensor_obstacle) && (sensor[chosen_dir+1] < sensor_obstacle) ) {
			Vector_Drive(Z, 0.500); 
			chosen_dir=0; }
		else {
			// sensor+1 -> clear  & sensor+2 -> obstacle
			if ( (sensor[chosen_dir+1] > sensor_clearview) && (sensor[chosen_dir+2] < sensor_obstacle) ) 
				chosen_dir+=1;
			// sensor+1 -> obstalce & sensor+2 -> clear
			if ( (sensor[chosen_dir+1] < sensor_obstacle) && (sensor[chosen_dir+2] > sensor_clearview) ) 
				chosen_dir+=2;
			// sensor+1 -> clear & sensor+2 -> clear
			if ( (sensor[chosen_dir+2] > sensor_clearview) && (sensor[chosen_dir+1] > sensor_clearview) ) 
				// pick 2 for now, change to random later
				chosen_dir+=2;
			if ((chosen_dir) > 3)
				chosen_dir-=3;	// prevent overflow
			Move(chosen_dir); }
			Display(chosen_dir);
	} while (quit_loop==0);
	StopRobot();
}

/****************************************************************************/

// Suspends application for specified number of ticks

void
Wait(int delay_ticks)
{
	usleep(delay_ticks * 10000);
}

// Pauses application for specified number of ticks
// Can be interrupted by penDown event
// Returns 1 if it was interrupted by penDown
// Returns 0 if delay ended with no interrupts

int
SmartWait(int delay_ticks)
{
	fd_set rfds;
	struct timeval tv;

	FD_ZERO(&rfds);
	FD_SET(ir_fd, &rfds);
	tv.tv_sec = 0;
	tv.tv_usec = delay_ticks * 10000;

	if (select(ir_fd + 1, &rfds, NULL, NULL, &tv) == 0)
		return(0);
	return(1);
}

/****************************************************************************/

void
DisplayTxt(const char * str)
{
	syslog(LOG_INFO, "MSG: %s\n", str);
}

void
Display(int number)
{
	syslog(LOG_INFO, "NUM: %d\n", number);
}

void
DisplayIR(int sensor, int value)
{
	syslog(LOG_INFO, "SEN: %d %d\n", sensor, value);
}

/****************************************************************************/

void
Turn(int direction, int speed)
{
	switch(speed) {
		case Fast:
			switch(direction) {
				case Right:	Drive(200,200,200); break;
				case Left:	Drive(50,50,50); 	break;
			}
			break;
		case Slow:
			switch(direction) {
				case Right:	Drive(140,140,140); break;
				case Left:	Drive(100,100,100); break;
			}
			break;
	}
}

/****************************************************************************/
// Drives robot perpendicular to given servo
// (Given servo can be sued for steering)

void
Move(int direction)
{
	switch(direction) {
		case RToServo1: 		Drive(0,200,50); break;
		case RToServo2: 		Drive(50,0,200); break;
		case RToServo3: 		Drive(200,50,0); break;
		case (ToServo1+3):		Drive(0,50,200); break;
		case (ToServo2+3):		Drive(200,0,50); break;
		case ToServo1: 			Drive(0,50,200); break;
		case ToServo2:			Drive(200,0,50); break;
		case ToServo3:			Drive(50,200,0); break;
	}
}

/****************************************************************************/
// Drives robot parallel to given servo

void
PMove(int direction)
{
	switch(direction) {
		case ToServo1:
			Drive(200,113,113);
			break;
		case ToServo2:
			Drive(50,0,200);
			break;
		case ToServo3:
			Drive(200,50,0);
			break;
		case RToServo1:
			Drive(50,136,136);
			break;
		case RToServo2:
			Drive(200,0,50);
			break;
		case RToServo3:
			Drive(50,200,0);
			break;
	}
}

/****************************************************************************/
// Drives robot in a given direction vector V with given angular 
// velocity omega.
// r - wheel radius in meters
// b - wheel baseline in meters

void
Vector_Drive(vector V, double omega)
{
	vector F1(-1.000,0.000), F2(0.500,-0.866), F3(0.866,0.500);
	double omega1, omega2, omega3, b=0.090, r=0.020, h=0;
	omega1 = ( F1*V + b*omega ) / r;	// F1*V is overloaded dot product
	omega2 = ( F2*V + b*omega ) / r;
	omega3 = ( F3*V + b*omega ) / r;
	// makes sure that given path is physically possible
	if ( (omega1>6) || (omega2>6) || (omega3>6) || (omega1<-6) || (omega2<-6) || (omega3<-6) )
		DisplayTxt("Vectors: ERROR!");
	else 
		Drive(Vel_To_Value(omega1),Vel_To_Value(omega2),Vel_To_Value(omega3));
}

/****************************************************************************/
// Stops robot.

void
StopRobot(void)
{
	Drive(0,0,0);
}

/****************************************************************************/
// Update all 3 drive servos

void
Drive(int sv1, int sv2, int sv3)
{
  Servo(1, sv1);
  Servo(2, sv2);
  Servo(3, sv3);
}

/****************************************************************************/
// Calculates distance using Power Regression y=a*x^b
// returns value in cm ranging from 10 to 80

int
Sensor_To_Range(int x)
{
	double	a = 2141.72055;
	double	b = -1.078867;
	int		y = 100;

	if (x > 0)		y = (int) (a * pow((double)x, b));
	if (y < 10)		y = 10;
	if (y > 100)	y = 100;

	return y;
}

/****************************************************************************/
// Calculates servo value using Cubic Regression y=a*x^3+b*x^2+c*x+d
// Converts velocity in rad per second to servo value (0-255)
// vel can only be [-6,6] rad/sec
// x can only be [-1,1] rev/sec

int
Vel_To_Value(double vel)
{
	double x;
	x = vel / PI / 2;	// convert rad/sec to rev/sec
	if ( (vel>-6) && (vel<6) )
		return (int) (39.8053*x*x*x - 12.6083*x*x + 22.1197*x + 128.4262);
	return 0;
}

/****************************************************************************/

void
run_shell()
{
	pid_t	pid;
	int		status;

	if ((pid = vfork()) == 0) {
		execl("/bin/sh", "sh", NULL);
		_exit(1);
	}
	if (pid != (pid_t) -1)
		wait(&status);
}

/****************************************************************************/

void
spin_right()
{
	Turn(Right, Fast);
}

void
spin_left()
{
	Turn(Left, Fast);
}

void
forward()
{
	// Move(ToServo1);
	// Move(ToServo2);
	Move(ToServo3);
}

void
reverse()
{
	// Move(ToServo1);
	// Move(ToServo2);
	Move(RToServo3);
}

/****************************************************************************/

void
timed_turn(int dir, int speed)
{
	fd_set rfds;
	struct timeval tv;

	Turn(dir, speed);

	tv.tv_sec = 3;
	tv.tv_usec = 0;
	FD_ZERO(&rfds);
	FD_SET(ir_fd, &rfds);
	if (select(ir_fd + 1, &rfds, NULL, NULL, &tv) == 1)
		return;
	
	StopRobot();
}

void
timed_right_fast()
{
	timed_turn(Right, Fast);
}

void
timed_right_slow()
{
	timed_turn(Right, Slow);
}

void
timed_left_fast()
{
	timed_turn(Left, Fast);
}

void
timed_left_slow()
{
	timed_turn(Left, Slow);
}

void
timed_left_right_fast()
{
	timed_turn(Left, Fast);
	timed_turn(Right, Fast);
}

void
timed_left_right_slow()
{
	timed_turn(Left, Slow);
	timed_turn(Right, Slow);
}

/****************************************************************************/

void
led_flash()
{
	ledman_cmd(LEDMAN_CMD_FLASH, LEDMAN_COM1_RX);
	ledman_cmd(LEDMAN_CMD_FLASH, LEDMAN_NVRAM_2);
	ledman_cmd(LEDMAN_CMD_FLASH, LEDMAN_VPN);
}

void
led_nite()
{
	fd_set rfds;
	struct timeval tv;
	int n = 0;

	while (1) {
		tv.tv_sec = 0;
		tv.tv_usec = 100000;
		FD_ZERO(&rfds);
		FD_SET(ir_fd, &rfds);
		if (select(ir_fd + 1, &rfds, NULL, NULL, &tv) == 1)
			return;
		ledman_cmd(((1<<n) & 0x204) ? LEDMAN_CMD_ON : LEDMAN_CMD_OFF, LEDMAN_COM1_RX);
		ledman_cmd(((1<<n) & 0x108) ? LEDMAN_CMD_ON : LEDMAN_CMD_OFF, LEDMAN_NVRAM_2);
		ledman_cmd(((1<<n) & 0x090) ? LEDMAN_CMD_ON : LEDMAN_CMD_OFF, LEDMAN_VPN);
		n = (n + 1) % 12;
	}
}

void
led_reset()
{
	ledman_cmd(LEDMAN_CMD_RESET, LEDMAN_COM1_RX);
	ledman_cmd(LEDMAN_CMD_RESET, LEDMAN_NVRAM_2);
	ledman_cmd(LEDMAN_CMD_RESET, LEDMAN_VPN);
}

/****************************************************************************/

void
init_serial(char *dev)
{
	struct termios tio;

	serial_fd = open(dev, O_RDWR);
	if (serial_fd == -1) {
		syslog(LOG_INFO, "Failed to open serial port: %s\n", strerror(errno));
		exit(1);
	}
	memset(&tio, 0, sizeof(tio));

	tio.c_cflag = B9600 | CREAD | CLOCAL | CS8;
	tio.c_cc[VMIN] = 1;
	tio.c_cc[VTIME] = 0;

	if (tcsetattr(serial_fd, TCSAFLUSH, &tio) < 0) {
		syslog(LOG_INFO, "Failed to tcsetattr: %s\n", strerror(errno));
		exit(1);
	}
}

/****************************************************************************/

void
init_lircd(char *file)
{
	struct sockaddr_un addr;

	memset(&addr, 0, sizeof(addr));
	addr.sun_family=AF_UNIX;
	strcpy(addr.sun_path, file);

	ir_fd = socket(AF_UNIX,SOCK_STREAM,0);
	if (ir_fd == -1) {
		syslog(LOG_INFO, "socket: %s\n", strerror(errno));
		exit(1);
	}
	if (connect(ir_fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
		syslog(LOG_INFO, "connect: %s\n", strerror(errno));
		exit(1);
	}
}

/****************************************************************************/

char *
get_irkey()
{
	fd_set		rfds;
	static char	buf[128];
	static char	code[128];
	static char	key[128];
	static char	type[128];
	char		*cp;
	int			n = -1;

	FD_ZERO(&rfds);
	FD_SET(ir_fd, &rfds);
	if (select(ir_fd + 1, &rfds, NULL, NULL, NULL) != 1) {
		syslog(LOG_INFO, "error on IR: %s\n", strerror(errno));
		exit(1);
	}
	n = read(ir_fd, buf, sizeof(buf));
	if (n <= 0) {
		syslog(LOG_INFO, "read %d\n", n);
		exit(1);
	}
	if (cp = strchr(buf, '\n'))
		*cp = '\0';
	if (sscanf(buf, "%s %d %s %s", code, &n, key, type) != 4) {
		syslog(LOG_INFO, "bad IR line '%s'", buf);
		return("bad");
	}
	/*
	 *	only the first key press
	 */
	if (n == 0)
		return(key);
	return(NULL);
}

/****************************************************************************/

static struct {
	char *key_name;
	void (*func)(void);
} command[] = {
	{ "mute",     StopRobot },				/* keep me first, stop everything */

	{ "0",        run_shell },				/* disaster recovery */
	{ "1",        led_flash },
	{ "2",        led_nite },
	{ "3",        led_reset },

	{ "4",        timed_right_fast },
	{ "5",        timed_left_fast },
	{ "6",        timed_left_right_fast },

	{ "7",        timed_right_slow },
	{ "8",        timed_left_slow },
	{ "9",        timed_left_right_slow },

	{ "chan+",    spin_right },
	{ "chan-",    spin_left },

	{ "vol+",     forward },
	{ "vol-",     reverse },

#if 0
	{ "1",        spin_left },				/* simple turn/forward contols */
	{ "2",        forward },
	{ "3",        spin_right },
	{ "4",        SpinAlgorithm },
	{ "5",        WallFollowAlgorithm },
	{ "6",        TravelerAlgorithm },
	{ "7",        PenFollowAlgorithm },
#endif

	{ NULL,       NULL }
};

/****************************************************************************/

main(int argc, char *argv[])
{
	char	*opt;
	int		i, n;

	init_serial("/dev/ttyS0");
	init_lircd("/var/tmp/lircd");

	if (argc == 2 && strcmp(argv[1], "test") == 0) {
		simple_test();
		exit(0);
	}
	
	StopRobot(); /* turn it off to start with */

	n = 0;
	do {
		opt = get_irkey();
		if (opt) {
			syslog(LOG_INFO, "PalmBot - %s\n", opt);
			for (i = 0; command[i].key_name; i++)
				if (strcmp(command[i].key_name, opt) == 0) {
					n = i;
					break;
				}
		}
		if (command[n].key_name) {
			syslog(LOG_INFO, "Run command '%s'\n", command[n].key_name);
			(*command[n].func)();
		}
	} while (command[n].key_name);

	StopRobot(); /* turn it off to end with */

	exit(0);
}

/****************************************************************************/
