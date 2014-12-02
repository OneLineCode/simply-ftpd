#include "util.h"


void strTrimCrlf(char *str)
{
	char *p = &str[strlen(str)-1];
	while (*p == '\r' || *p == '\n')
		*p-- = '\0';

}

void strSplit(const char *str , char *left, char *right, char c)
{
	const char *p = strchr(str, c);
	if (p == NULL)
		strcpy(left, str);
	else
	{
		strncpy(left, str, p-str);
		strcpy(right, p+1);
	}
}

int strAllSpace(const char *str)
{
	while (*str)
	{
		if (!isspace(*str))
			return 0;
		str++;
	}
	return 1;
}

void strUpper(char *str)
{
	while (*str)
	{
		*str = toupper(*str);
		str++;
	}
}

long long strToLonglong(const char *str)
{
	long long result = 0;
	long long mult = 1;
	unsigned int len = strlen(str);
	int i; // unsigned int i;会陷入死循环

	if (len > 15)
		return 0;

	for (i=len-1; i>=0; i--)
	{
		char ch = str[i];
		long long val;
		if (ch < '0' || ch > '9')
			return 0;

		val = ch - '0';
		val *= mult;
		result += val;
		mult *= 10;
	}

	return result;
}

unsigned int strOctalToUint(const char *str)
{
	unsigned int result = 0;
	int seen_non_zero_digit = 0;

	while (*str)
	{
		int digit = *str;
		if (!isdigit(digit) || digit > '7')
			break;

		if (digit != '0')
			seen_non_zero_digit = 1;

		if (seen_non_zero_digit)
		{
			result <<= 3;
			result += (digit - '0');
		}
		str++;
	}
	return result;
}

void praseCmd(char* cmdline, char* cmd, char* arg)
{
	// 去除\r\n
	strTrimCrlf(cmdline);
	log("cmdline=[%s]\n", cmdline);
	// 解析FTP命令与参数
	strSplit(cmdline, cmd, arg, ' ');
	log("cmd=[%s] arg=[%s]\n", cmd, arg);
	// 将命令转换为大写
	strUpper(cmd);
}

const char* statGetPerms(struct stat *sbuf)
{
	static char perms[] = "----------";
	perms[0] = '?';

	mode_t mode = sbuf->st_mode;
	switch (mode & S_IFMT)
	{
	case S_IFREG:
		perms[0] = '-';
		break;
	case S_IFDIR:
		perms[0] = 'd';
		break;
	case S_IFLNK:
		perms[0] = 'l';
		break;
	case S_IFIFO:
		perms[0] = 'p';
		break;
	case S_IFSOCK:
		perms[0] = 's';
		break;
	case S_IFCHR:
		perms[0] = 'c';
		break;
	case S_IFBLK:
		perms[0] = 'b';
		break;
	}

	if (mode & S_IRUSR)
	{
		perms[1] = 'r';
	}
	if (mode & S_IWUSR)
	{
		perms[2] = 'w';
	}
	if (mode & S_IXUSR)
	{
		perms[3] = 'x';
	}
	if (mode & S_IRGRP)
	{
		perms[4] = 'r';
	}
	if (mode & S_IWGRP)
	{
		perms[5] = 'w';
	}
	if (mode & S_IXGRP)
	{
		perms[6] = 'x';
	}
	if (mode & S_IROTH)
	{
		perms[7] = 'r';
	}
	if (mode & S_IWOTH)
	{
		perms[8] = 'w';
	}
	if (mode & S_IXOTH)
	{
		perms[9] = 'x';
	}
	if (mode & S_ISUID)
	{
		perms[3] = (perms[3] == 'x') ? 's' : 'S';
	}
	if (mode & S_ISGID)
	{
		perms[6] = (perms[6] == 'x') ? 's' : 'S';
	}
	if (mode & S_ISVTX)
	{
		perms[9] = (perms[9] == 'x') ? 't' : 'T';
	}

	return perms;
}

const char* statGetDate(struct stat *sbuf)
{
	static char datebuf[64] = {0};
	const char *p_date_format = "%b %e %H:%M";
	struct timeval tv;
	gettimeofday(&tv, NULL);
	time_t local_time = tv.tv_sec;
	if (sbuf->st_mtime > local_time || (local_time - sbuf->st_mtime) > 60*60*24*182)
	{
		p_date_format = "%b %e  %Y";
	}

	struct tm* p_tm = localtime(&local_time);
	strftime(datebuf, sizeof(datebuf), p_date_format, p_tm);

	return datebuf;
}

static int lockInternal(int fd, int lock_type)
{
	int ret;
	struct flock the_lock;
	memset(&the_lock, 0, sizeof(the_lock));
	the_lock.l_type = lock_type;
	the_lock.l_whence = SEEK_SET;
	the_lock.l_start = 0;
	the_lock.l_len = 0;
	do
	{
		ret = fcntl(fd, F_SETLKW, &the_lock);
	}
	while (ret < 0 && errno == EINTR);

	return ret;
}

int lockFileRead(int fd)
{
	return lockInternal(fd, F_RDLCK);
}


int lockFileWrite(int fd)
{
	return lockInternal(fd, F_WRLCK);
}


int unlockFile(int fd)
{
	int ret;
	struct flock the_lock;
	memset(&the_lock, 0, sizeof(the_lock));
	the_lock.l_type = F_UNLCK;
	the_lock.l_whence = SEEK_SET;
	the_lock.l_start = 0;
	the_lock.l_len = 0;

	ret = fcntl(fd, F_SETLK, &the_lock);

	return ret;
}

static struct timeval s_curr_time;
long getTimeSec(void)
{
	if (gettimeofday(&s_curr_time, NULL) < 0)
	{
		log_exit("gettimeofday");
	}

	return s_curr_time.tv_sec;
}

long getTimeUsec(void)
{
	return s_curr_time.tv_usec;
}

void nanoSleep(double seconds)
{
	time_t secs = (time_t)seconds;					// 整数部分
	double fractional = seconds - (double)secs;		// 小数部分

	struct timespec ts;
	ts.tv_sec = secs;
	ts.tv_nsec = (long)(fractional * (double)1000000000);
	
	int ret;
	do
	{
		ret = nanosleep(&ts, &ts);
	}
	while (ret == -1 && errno == EINTR);
}

static void formatTime(FILE* fp)
{
	struct timeval tval;
	struct tm* tm;
	time_t currTime;

	time(&currTime);
	tm = localtime(&currTime);
	gettimeofday(&tval, NULL);
	fprintf(fp, "[%04d-%02d-%02d %02d:%02d:%02d.%03d]", 1900 + tm->tm_year, 1 + tm->tm_mon,
		tm->tm_mday, tm->tm_hour, tm->tm_min, tm->tm_sec, (int)tval.tv_usec / 1000);
}

void logger(const char* fmt, ...)
{
	static int file_no = 1;
	static FILE* log_fp = NULL;
	if (log_fp == NULL)
	{
		uint32_t pid = 0;
		pid = (uint32_t)getpid();

#ifdef _LOGSCR
		log_fp = stderr;
#else
		char log_name[64];
		snprintf(log_name, 64, "log_%d_%d.txt", pid, file_no);
		log_fp = fopen(log_name, "w");
		if (log_fp == NULL)
			return;
#endif
	}

	formatTime(log_fp);

	va_list ap;
	va_start(ap, fmt);
	vfprintf(log_fp, fmt, ap);
	va_end(ap);
	fprintf(log_fp, "\n");
	fflush(log_fp);

	if (ftell(log_fp) > MAX_LOG_FILE_SIZE)
	{
		fclose(log_fp);
		log_fp = NULL;
		file_no++;
	}
}


