#ifndef _UTIL_H_
#define _UTIL_H_

#include "common.h"


void strTrimCrlf(char *str);
void strSplit(const char *str , char *left, char *right, char c);
int strAllSpace(const char *str);
void strUpper(char *str);
long long strToLonglong(const char *str);
unsigned int strOctalToUint(const char *str);


void praseCmd(char* cmdline, char* cmd, char* arg);


const char* statGetPerms(struct stat *sbuf);
const char* statGetDate(struct stat *sbuf);

int lockFileRead(int fd);
int lockFileWrite(int fd);
int unlockFile(int fd);

long getTimeSec(void);
long getTimeUsec(void);
void nanoSleep(double seconds);




/* ºÚ“◊»’÷æ */

#define log(fmt, args...)  logger("[%s]|[%d]|[%s]," fmt, __FILE__, __LINE__, __FUNCTION__, ##args)

/*
#define log_exit(m)  logger("[%s]|[%d]|[%s],", __FILE__, __LINE__, __FUNCTION__);\
								do \
								{ \
								  perror(m); \
								  exit(EXIT_FAILURE); \
								} \
								while (0)
*/									

#define log_exit(m) \
	  do \
	  { \
		perror(m); \
		exit(EXIT_FAILURE); \
	  } \
	  while (0)



void logger(const char* fmt, ...);


#endif /* _UTIL_H_ */

