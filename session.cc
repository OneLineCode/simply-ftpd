#include "common.h"
#include "session.h"
#include "inner.h"
#include "util.h"
#include "socket.h"
#include "config.h"

Session* g_SessPtr = NULL;

std::map<std::string, int> cmd_map;



enum E_CMD
{
	USER,
	PASS,
	CWD,
	XCWD,
	CDUP,
	XCUP,
	QUIT,
	ACCT,
	SMNT,
	REIN, 
	PORT,
	PASV,
	TYPE,
	STRU,
	MODE,
	RETR,
	STOR,
	APPE,
	LIST,
	NLST,
	REST,
	ABOR,
	PWD,	
	MKD,	
	RMD,	
	DELE,
	RNFR,
	RNTO,
	SITE,
	SYST,
	FEAT,
	SIZE,
	STAT,
	NOOP,
	HELP,
	UNCOMPLETE,
};

ftpcmd_t cmd_array[] = {
	/* 访问控制命令 */
	{"USER",	USER	},
	{"PASS",	PASS	},
	{"CWD", 	CWD	},
	{"XCWD",	XCWD	},
	{"CDUP",	CDUP	},
	{"XCUP",	XCUP	},
	{"QUIT",	QUIT	},
	{"ACCT",	ACCT	},
	{"SMNT",	SMNT	},
	{"REIN",	REIN	},
	/* 传输参数命令 */
	{"PORT",	PORT	},
	{"PASV",	PASV	},
	{"TYPE",	TYPE	},
	{"STRU",	STRU },
	{"MODE",	MODE },

	/* 服务命令 */
	{"RETR",	RETR	},
	{"STOR",	STOR	},
	{"APPE",	APPE	},
	{"LIST",	LIST	},
	{"NLST",	NLST },
	{"REST",	REST	},
	{"ABOR",	ABOR	},
	{"\377\364\377\362ABOR", ABOR},
	{"PWD", 	PWD	},
	{"XPWD",	PWD	},
	{"MKD", 	MKD	},
	{"XMKD",	MKD	},
	{"RMD", 	RMD	},
	{"XRMD",	RMD	},
	{"DELE",	DELE	},
	{"RNFR",	RNFR	},
	{"RNTO",	RNTO	},
	{"SITE",	SITE	},
	{"SYST",	SYST	},
	{"FEAT",	FEAT },
	{"SIZE",	SIZE	},
	{"STAT",	STAT	},
	{"NOOP",	NOOP	},
	{"HELP",	HELP	},
	{"STOU",	UNCOMPLETE	},
	{"ALLO",	UNCOMPLETE	},
	{NULL, NULL} /* 结束标志 */
};

Session::Session(int conn, unsigned int  ip)
{
	num_clients++;
	
	// 控制连接
	uid_= 0;
	ctrlFd_ = conn;
	memset(cmdline_, 0, sizeof(cmdline_));
	memset(cmd_, 0, sizeof(cmd_));
	memset(arg_, 0, sizeof(arg_));

	// 数据连接
	portAddr_ = NULL;
	pasv_listen_fd_ = -1;
	dataFd_ = -1;
	//data_process_ = 0;
	isTransferring_ = false;

	// 父子进程通道
	parentFd_ = -1;
	childFd_ = -1;

	// FTP协议状态
	is_ascii_ = 0;
	restart_pos_ = 0;
	rnfr_name_= NULL;
	abor_ = false;

	ip_ = ip;


}
Session::~Session()
{
	num_clients--;
}

unsigned int Session::num_clients = 0;

void Session::start()
{
	g_SessPtr = this;
	checkLimits();
	activateOobinline(ctrlFd_);

	//InInit(sess);
	int sockfds[2];
	if (socketpair(PF_UNIX, SOCK_STREAM, 0, sockfds) < 0)
		log_exit("socketpair");
	parentFd_ = sockfds[0];
	childFd_ = sockfds[1];

	pid_t pid;
	pid = fork();
	if (pid < 0)
		log_exit("fork");

	if (pid == 0)
	{
		// ftp服务进程  保留childFd
		close(parentFd_);
		runServiceProcess();
	}
	else
	{
		// nobody进程 保留parentFd
		close(childFd_);
		runNobodyProcess();
	}
}

void Session::checkLimits()
{
	if (g_cfg.max_clients > 0 && Session::num_clients > g_cfg.max_clients)
	{
		ftp_reply(FTP_TOO_MANY_USERS, 
			"There are too many connected users, please try later.");

		exit(EXIT_FAILURE);
	}

	if (g_cfg.max_per_ip > 0 && ipCountMap[ip_] > (int)g_cfg.max_per_ip)
	{
		ftp_reply(FTP_IP_LIMIT, 
			"There are too many connections from your internet address.");

		exit(EXIT_FAILURE);
	}
}

void Session::runServiceProcess()
{
	ftp_reply(FTP_GREET, "(ftpd 0.1)");
	int ret;
	while (1)
	{
		memset(cmdline_, 0, sizeof(cmdline_));
		memset(cmd_, 0, sizeof(cmd_));
		memset(arg_, 0, sizeof(arg_));

		startSessionAlarm();
		ret = readline(ctrlFd_, cmdline_, MAX_COMMAND_LINE);
		if (ret == -1)
		{
			log_exit("readline");
		}
		else if (ret == 0)
			exit(EXIT_SUCCESS);

		log("cmdline=[%s]\n", cmdline_);

		praseCmd(cmdline_, cmd_, arg_);

		switch(cmd_map[cmd_])
		{
		case USER:
			onUser();
			break;
		case PASS:
			onPass();
			break;
		case CWD:
		case XCWD:
			onCwd();
			break;
		case CDUP:
		case XCUP:
			onCdUp();
			break;
		case QUIT:
			onQuit();
			break;
		case ACCT:
			;
			break;
		case SMNT:
			;
			break;
		case REIN:
			;
			break;
		case PORT:
			onPort();
			break;
		case PASV:
			onPasv();
			break;
		case TYPE:
			onType();
			break;
		case STRU:
			;
			break;
		case MODE:
			;
			break;
		case RETR:
			onRetr();
			break;
		case STOR:
			onStor();
			break;
		case APPE:
			onAppe();
			break;
		case LIST:
			onList();
			break;
		case NLST:
			onNlist();
			break;
		case REST:
			onRest();
			break;
		case ABOR:
			onAbor();
			break;
		case PWD:
			onPwd();
			break;
		case MKD:	
			onMkd();
			break;
		case RMD:
			onRmd();
			break;
		case DELE:
			onDele();
			break;
		case RNFR:
			onRnfr();
			break;
		case RNTO:
			onRnto();
			break;
		case SITE:
			onSite();
			break;
		case SYST:
			onSyst();
			break;
		case FEAT:
			onFeat();
			break;
		case SIZE:
			onSize();
			break;
		case STAT:
			onStat();
			break;
		case NOOP:
			onNoop();
			break;
		case HELP:
			onHelp();
			break;
		default :
			ftp_reply(FTP_BADCMD, "Unknown command.");
			break;
		}
	}
}
void Session::runNobodyProcess()
{
	minimize_privilege();

	char cmd;
	while (1)
	{
		//read(sess->parent_fd, &cmd, 1);
		cmd = InGetCmd(parentFd_);
		// 解析内部命令
		// 处理内部命令
		switch (cmd)
		{
		case INNER_GET_DATA_FD:
			innerGetDataFd();
			break;
		case INNER_ACTIVE_PASV:
			innerPasvActive();
			break;
		case INNER_PASV_LISTEN:
			innerPasvListen();
			break;
		case INNER_PASV_ACCEPT:
			innerPasvAccept();
			break;
		}
	}
}


int Session::getCtrlFd()
{
	return ctrlFd_;
}

int Session::getDataFd()
{
	return dataFd_;
}

bool Session::getTransferring()
{
	return isTransferring_;
}
void Session::setTransferring(bool isTransferring)
{
	isTransferring_ = isTransferring;
}

void Session::setAbor(bool abor)
{
	abor_ = abor;
}



void Session::ftp_reply(int status, const char *text)
{
	char buf[1024] = {0};
	sprintf(buf, "%d %s\r\n", status, text);
	writen(ctrlFd_ , buf, strlen(buf));
}

void Session::ftp_reply(int ctrlFd, int status, const char *text)
{
	char buf[1024] = {0};
	sprintf(buf, "%d %s\r\n", status, text);
	writen(ctrlFd , buf, strlen(buf));
}

void Session::ftp_lreply(int status, const char *text)
{
	char buf[1024] = {0};
	sprintf(buf, "%d-%s\r\n", status, text);
	writen(ctrlFd_ , buf, strlen(buf));
}


void Session::handleAlarmTimeout(int sig)
{
	shutdown(g_SessPtr->getCtrlFd(), SHUT_RD);
	ftp_reply(g_SessPtr->getCtrlFd(), FTP_IDLE_TIMEOUT, "Timeout.");
	shutdown(g_SessPtr->getCtrlFd(), SHUT_WR);
	exit(EXIT_FAILURE);
}

void Session::handleSigalrm(int sig)
{
	if (!g_SessPtr->getTransferring())
	{
		ftp_reply(g_SessPtr->getCtrlFd(), FTP_DATA_TIMEOUT, "Data timeout. Reconnect. Sorry.");
		exit(EXIT_FAILURE);
	}

	// 否则，当前处于数据传输的状态收到了超时信号 重新启动闹钟
	g_SessPtr->setTransferring(false);
	g_SessPtr->startDataAlarm();
}

void Session::handleSigurg(int sig)
{
	if (g_SessPtr->getDataFd() == -1)
	{
		return;
	}

	char cmdline[MAX_COMMAND_LINE] = {0};
	int ret = readline(g_SessPtr->getCtrlFd(), cmdline, MAX_COMMAND_LINE);
	if (ret <= 0)
	{
		log_exit("readline");
	}
	strTrimCrlf(cmdline);
	if (strcmp(cmdline, "ABOR") == 0
		|| strcmp(cmdline, "\377\364\377\362ABOR") == 0)
	{
		g_SessPtr->setAbor(true);
		shutdown(g_SessPtr->getDataFd(), SHUT_RDWR);
	}
	else
	{
		ftp_reply(g_SessPtr->getCtrlFd(), FTP_BADCMD, "Unknown command.");
	}
}

void Session::checkAbor()
{
	if (abor_)
	{
		abor_ = 0;
		ftp_reply(FTP_ABOROK, "ABOR successful.");
	}
}

void Session::startSessionAlarm(void)
{
	if (g_cfg.idle_session_timeout > 0)
	{
		// 安装信号
		signal(SIGALRM, handleAlarmTimeout);
		// 启动闹钟
		alarm(g_cfg.idle_session_timeout);
	}
}

void Session::startDataAlarm(void)
{
	if (g_cfg.data_connection_timeout > 0)
	{
		// 安装信号
		signal(SIGALRM, handleSigalrm);
		// 启动闹钟
		alarm(g_cfg.data_connection_timeout);
	}
	else if (g_cfg.idle_session_timeout > 0)
	{
		// 关闭先前安装的闹钟
		alarm(0);
	}
}

int Session::list(int detail)
{
	DIR *dir = opendir(".");
	if (dir == NULL)
	{
		return 0;
	}

	struct dirent *dt;
	struct stat sbuf;
	while ((dt = readdir(dir)) != NULL)
	{
		if (lstat(dt->d_name, &sbuf) < 0)
		{
			continue;
		}
		if (dt->d_name[0] == '.')
			continue;

		char buf[1024] = {0};
		if (detail)
		{
			const char *perms = statGetPerms(&sbuf);

			
			int off = 0;
			off += sprintf(buf, "%s ", perms);
			off += sprintf(buf + off, " %3d %-8d %-8d ", sbuf.st_nlink, sbuf.st_uid, sbuf.st_gid);
			off += sprintf(buf + off, "%8lu ", (unsigned long)sbuf.st_size);

			const char *datebuf = statGetDate(&sbuf);
			off += sprintf(buf + off, "%s ", datebuf);
			if (S_ISLNK(sbuf.st_mode))
			{
				char tmp[1024] = {0};
				readlink(dt->d_name, tmp, sizeof(tmp));
				off += sprintf(buf + off, "%s -> %s\r\n", dt->d_name, tmp);
			}
			else
			{
				off += sprintf(buf + off, "%s\r\n", dt->d_name);
			}
		}
		else
		{
			sprintf(buf, "%s\r\n", dt->d_name);
		}
		
		writen(dataFd_, buf, strlen(buf));
	}

	closedir(dir);

	return 1;
}

void Session::limitRate(int bytes_transfered, int is_upload)
{
	isTransferring_ = 1;

	// 睡眠时间 = (当前传输速度 / 最大传输速度 – 1) * 当前传输时间;
	long curr_sec = getTimeSec();
	long curr_usec = getTimeUsec();

	double elapsed;
	elapsed = (double)(curr_sec - bw_transfer_start_sec);
	elapsed += (double)(curr_usec - bw_transfer_start_usec) / (double)1000000;
	if (elapsed <= (double)0)
	{
		elapsed = (double)0.01;
	}


	// 计算当前传输速度
	unsigned int bw_rate = (unsigned int)((double)bytes_transfered / elapsed);

	double rate_ratio;
	if (is_upload)
	{
		if (bw_rate <= bw_upload_rate_max)
		{
			// 不需要限速
			bw_transfer_start_sec = curr_sec;
			bw_transfer_start_usec = curr_usec;
			return;
		}

		rate_ratio = bw_rate / bw_upload_rate_max;
	}
	else
	{
		if (bw_rate <= bw_download_rate_max)
		{
			// 不需要限速
			bw_transfer_start_sec = curr_sec;
			bw_transfer_start_usec = curr_usec;
			return;
		}

		rate_ratio = bw_rate / bw_download_rate_max;
	}

	// 睡眠时间 = (当前传输速度 / 最大传输速度 – 1) * 当前传输时间;
	double pause_time;
	pause_time = (rate_ratio - (double)1) * elapsed;

	nanoSleep(pause_time);

	bw_transfer_start_sec = getTimeSec();
	bw_transfer_start_usec = getTimeUsec();

}

void Session::upload(int is_append)
{
	// 创建数据连接
	if (getTransferFd() == 0)
	{
		return;
	}

	long long offset = restart_pos_;
	restart_pos_ = 0;

	// 打开文件
	int fd = open(arg_, O_CREAT | O_WRONLY, 0666);
	if (fd == -1)
	{
		ftp_reply(FTP_UPLOADFAIL, "Could not create file.");
		return;
	}

	int ret;
	// 加写锁
	ret = lockFileWrite(fd);
	if (ret == -1)
	{
		ftp_reply(FTP_UPLOADFAIL, "Could not create file.");
		return;
	}

	// STOR
	// REST+STOR
	// APPE
	if (!is_append && offset == 0)		// STOR
	{
		ftruncate(fd, 0);
		if (lseek(fd, 0, SEEK_SET) < 0)
		{
			ftp_reply(FTP_UPLOADFAIL, "Could not create file.");
			return;
		}
	}
	else if (!is_append && offset != 0)		// REST+STOR
	{
		if (lseek(fd, offset, SEEK_SET) < 0)
		{
			ftp_reply(FTP_UPLOADFAIL, "Could not create file.");
			return;
		}
	}
	else if (is_append)				// APPE
	{
		if (lseek(fd, 0, SEEK_END) < 0)
		{
			ftp_reply(FTP_UPLOADFAIL, "Could not create file.");
			return;
		}
	}
	struct stat sbuf;
	ret = fstat(fd, &sbuf);
	if (!S_ISREG(sbuf.st_mode))
	{
		ftp_reply(FTP_UPLOADFAIL, "Could not create file.");
		return;
	}

	// 150
	char text[1024] = {0};
	if (is_ascii_)
	{
		sprintf(text, "Opening ASCII mode data connection for %s (%lld bytes).",
			arg_, (long long)sbuf.st_size);
	}
	else
	{
		sprintf(text, "Opening BINARY mode data connection for %s (%lld bytes).",
			arg_, (long long)sbuf.st_size);
	}

	ftp_reply(FTP_DATACONN, text);

	int flag = 0;
	// 上传文件

	char buf[1024];

	bw_transfer_start_sec = getTimeSec();
	bw_transfer_start_usec = getTimeUsec();

	while (1)
	{
		ret = read(dataFd_, buf, sizeof(buf));
		if (ret == -1)
		{
			if (errno == EINTR)
			{
				continue;
			}
			else
			{
				flag = 2;
				break;
			}
		}
		else if (ret == 0)
		{
			flag = 0;
			break;
		}

		limitRate(ret, 1);
		if (abor_)
		{
			flag = 2;
			break;
		}

		if (writen(fd, buf, ret) != ret)
		{
			flag = 1;
			break;
		}
	}


	// 关闭数据套接字
	close(dataFd_);
	dataFd_ = -1;

	close(fd);

	if (flag == 0 && !abor_)
	{
		// 226
		ftp_reply(FTP_TRANSFEROK, "Transfer complete.");
	}
	else if (flag == 1)
	{
		// 451
		ftp_reply(FTP_BADSENDFILE, "Failure writting to local file.");
	}
	else if (flag == 2)
	{
		// 426
		ftp_reply(FTP_BADSENDNET, "Failure reading from network stream.");
	}

	checkAbor();
	// 重新开启控制连接通道闹钟
	startSessionAlarm();
}


int Session::portActive()
{
	if (portAddr_)
	{
		if (pasvActive())
		{
			fprintf(stderr, "both port an pasv are active");
			exit(EXIT_FAILURE);
		}
		return 1;
	}

	return 0;
}

int Session::pasvActive()
{
	InSendCmd(childFd_, INNER_ACTIVE_PASV);
	int active = InGetInt(childFd_);
	if (active)
	{
		if (portActive())
		{
			log_exit("both port an pasv are active");
		}
		return 1;
	}
	return 0;
}

int Session::getPortFd()
{
	/*
	向nobody发送PRIV_SOCK_GET_DATA_SOCK命令        1
	向nobody发送一个整数port		       4
	向nobody发送一个字符串ip                       不定长
	*/

	InSendCmd(childFd_, INNER_GET_DATA_FD);
	unsigned short port = ntohs(portAddr_->sin_port);
	char *ip = inet_ntoa(portAddr_->sin_addr);
	InGetInt(childFd_, (int)port);
	InSendIp(childFd_, ip, strlen(ip));

	char res = InGetResult(childFd_);
	if (res == INNER_BAD)
	{
		return 0;
	}
	else if (res == INNER_OK)
	{
		dataFd_ = InRecvFd(childFd_);
	}

	return 1;
}

int Session::getPasvFd()
{
	InSendCmd(childFd_, INNER_PASV_ACCEPT);
	char res = InGetResult(childFd_);
	if (res == INNER_BAD)
	{
		return 0;
	}
	else if (res == INNER_OK)
	{
		dataFd_ = InRecvFd(childFd_);
	}

	return 1;
}

int Session::getTransferFd()
{
	// 检测是否收到PORT或者PASV命令
	if (!portActive() && !pasvActive())
	{
		ftp_reply(FTP_BADSENDCONN, "Use PORT or PASV first.");
		return 0;
	}

	int ret = 1;
	// 如果是主动模式
	if (portActive())
	{
		if (getPortFd() == 0)
		{
			ret = 0;
		}
	}

	if (pasvActive())
	{
		if (getPasvFd() == 0)
		{
			ret = 0;
		}

	}

	
	if (portAddr_)
	{
		free(portAddr_);// 释放内存
		portAddr_ = NULL;
	}

	if (ret)
	{
		// 重新安装SIGALRM信号，并启动闹钟
		startDataAlarm();
	}

	return ret;
}

void Session::onUser()
{
	//USER jjl
	struct passwd *pw = getpwnam(arg_);
	if (pw == NULL)
	{
		// 用户不存在
		ftp_reply(FTP_LOGINERR, "Login incorrect.");
		return;
	}

	uid_ = pw->pw_uid;
	ftp_reply(FTP_GIVEPWORD, "Please specify the password.");
	
}

void Session::onPass()
{
	// PASS 123456
	struct passwd *pw = getpwuid(uid_);
	if (pw == NULL)
	{
		// 用户不存在
		ftp_reply(FTP_LOGINERR, "Login incorrect.");
		return;
	}

	log("name=[%s]\n", pw->pw_name);
	struct spwd *sp = getspnam(pw->pw_name);
	if (sp == NULL)
	{
		ftp_reply(FTP_LOGINERR, "Login incorrect.");
		return;
	}

	// 将明文进行加密
	char *encrypted_pass = crypt(arg_, sp->sp_pwdp);
	// 验证密码
	if (strcmp(encrypted_pass, sp->sp_pwdp) != 0)
	{
		ftp_reply(FTP_LOGINERR, "Login incorrect.");
		return;
	}

	signal(SIGURG, handleSigurg);
	activateSigurg(ctrlFd_);

	umask(g_cfg.local_umask);
	setegid(pw->pw_gid);
	seteuid(pw->pw_uid);
	chdir(pw->pw_dir);
	ftp_reply(FTP_LOGINOK, "Login successful.");
}

void Session::onCwd()
{
	if (chdir(arg_) < 0)
	{
		ftp_reply(FTP_FILEFAIL, "Failed to change directory.");
		return;
	}

	ftp_reply(FTP_CWDOK, "Directory successfully changed.");
}

void Session::onCdUp()
{
	if (chdir("..") < 0)
	{
		ftp_reply(FTP_FILEFAIL, "Failed to change directory.");
		return;
	}

	ftp_reply(FTP_CWDOK, "Directory successfully changed.");
}

void Session::onQuit()
{
	ftp_reply(FTP_GOODBYE, "Goodbye.");
	//delete(ss); //@这里释放内存 nobody进程中也需要delete吗
	exit(EXIT_SUCCESS);
}

void Session::onPort()
{
	//PORT 192,168,0,100,123,233
	unsigned int v[6];

	sscanf(arg_, "%u,%u,%u,%u,%u,%u", &v[2], &v[3], &v[4], &v[5], &v[0], &v[1]);
	portAddr_ = (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in));
	memset(portAddr_, 0, sizeof(struct sockaddr_in));
	portAddr_->sin_family = AF_INET;
	unsigned char *p = (unsigned char *)&portAddr_->sin_port;
	p[0] = v[0];
	p[1] = v[1];

	p = (unsigned char *)&portAddr_->sin_addr;
	p[0] = v[2];
	p[1] = v[3];
	p[2] = v[4];
	p[3] = v[5];

	ftp_reply(FTP_PORTOK, "PORT command successful. Consider using PASV.");
}

void Session::onPasv()
{
	//Entering Passive Mode (192,168,244,100,101,46).

	char ip[16] = {0};
	getlocalip(ip);

	InSendCmd(childFd_, INNER_PASV_LISTEN);
	unsigned short port = (int)InGetInt(childFd_);


	unsigned int v[4];
	sscanf(ip, "%u.%u.%u.%u", &v[0], &v[1], &v[2], &v[3]);
	char text[1024] = {0};
	sprintf(text, "Entering Passive Mode (%u,%u,%u,%u,%u,%u).", 
		v[0], v[1], v[2], v[3], port>>8, port&0xFF);

	ftp_reply(FTP_PASVOK, text);


}

void Session::onType()
{
	if (strcmp(arg_, "A") == 0)
	{
		is_ascii_ = 1;
		ftp_reply(FTP_TYPEOK, "Switching to ASCII mode.");
	}
	else if (strcmp(arg_, "I") == 0)
	{
		is_ascii_ = 0;
		ftp_reply(FTP_TYPEOK, "Switching to Binary mode.");
	}
	else
	{
		ftp_reply(FTP_BADCMD, "Unrecognised TYPE command.");
	}

}

void Session::onRetr()
{
	// 下载文件
	// 断点续载

	// 创建数据连接
	if (getTransferFd() == 0)
	{
		return;
	}

	long long offset = restart_pos_;
	restart_pos_ = 0;

	// 打开文件
	int fd = open(arg_, O_RDONLY);
	if (fd == -1)
	{
		ftp_reply(FTP_FILEFAIL, "Failed to open file.");
		return;
	}

	int ret;
	// 加读锁
	ret = lockFileRead(fd);
	if (ret == -1)
	{
		ftp_reply(FTP_FILEFAIL, "Failed to open file.");
		return;
	}

	// 判断是否是普通文件
	struct stat sbuf;
	ret = fstat(fd, &sbuf);
	if (!S_ISREG(sbuf.st_mode))
	{
		ftp_reply(FTP_FILEFAIL, "Failed to open file.");
		return;
	}

	if (offset != 0)
	{
		ret = lseek(fd, offset, SEEK_SET);
		if (ret == -1)
		{
			ftp_reply(FTP_FILEFAIL, "Failed to open file.");
			return;
		}
	}

//150 Opening BINARY mode data connection for /home/jjl/tmp/echocli.c (1085 bytes).

	// 150
	char text[1024] = {0};
	if (is_ascii_)
	{
		sprintf(text, "Opening ASCII mode data connection for %s (%lld bytes).",
			arg_, (long long)sbuf.st_size);
	}
	else
	{
		sprintf(text, "Opening BINARY mode data connection for %s (%lld bytes).",
			arg_, (long long)sbuf.st_size);
	}

	ftp_reply(FTP_DATACONN, text);

	int flag = 0;
	// 下载文件

	long long bytes_to_send = sbuf.st_size;
	if (offset > bytes_to_send)
	{
		bytes_to_send = 0;
	}
	else
	{
		bytes_to_send -= offset;
	}

	bw_transfer_start_sec = getTimeSec();
	bw_transfer_start_usec = getTimeUsec();
	while (bytes_to_send)
	{
		int num_this_time = bytes_to_send > 4096 ? 4096 : bytes_to_send;
		ret = sendfile(dataFd_, fd, NULL, num_this_time);
		if (ret == -1)
		{
			flag = 2;
			break;
		}

		limitRate(ret, 0);
		if (abor_)
		{
			flag = 2;
			break;
		}

		bytes_to_send -= ret;
	}

	if (bytes_to_send == 0)
	{
		flag = 0;
	}

	// 关闭数据套接字
	close(dataFd_);
	dataFd_ = -1;

	close(fd);

	

	if (flag == 0 && !abor_)
	{
		// 226
		ftp_reply(FTP_TRANSFEROK, "Transfer complete.");
	}
	else if (flag == 1)
	{
		// 451
		ftp_reply(FTP_BADSENDFILE, "Failure reading from local file.");
	}
	else if (flag == 2)
	{
		// 426
		ftp_reply(FTP_BADSENDNET, "Failure writting to network stream.");
	}

	checkAbor();
	// 重新开启控制连接通道闹钟
	startSessionAlarm();
	
}

void Session::onStor()
{
	upload(0);
}

void Session::onAppe()
{
	upload(1);
}

void Session::onList()
{
	// 创建数据连接
	if (getTransferFd() == 0)
	{
		return;
	}
	// 150
	ftp_reply(FTP_DATACONN, "Here comes the directory listing.");

	// 传输列表
	list(1);
	// 关闭数据套接字
	close(dataFd_);
	dataFd_ = -1;
	// 226
	ftp_reply(FTP_TRANSFEROK, "Directory send OK.");

}

void Session::onNlist()
{
	// 创建数据连接
	if (getTransferFd() == 0)
	{
		return;
	}
	// 150
	ftp_reply(FTP_DATACONN, "Here comes the directory listing.");

	// 传输列表
	list(0);
	// 关闭数据套接字
	close(dataFd_);
	dataFd_ = -1;
	// 226
	ftp_reply(FTP_TRANSFEROK, "Directory send OK.");
}

void Session::onRest()
{
	restart_pos_ = strToLonglong(arg_);
	char text[1024] = {0};
	sprintf(text, "Restart position accepted (%lld).", restart_pos_);
	ftp_reply(FTP_RESTOK, text);
}

void Session::onAbor()
{
	ftp_reply(FTP_ABOR_NOCONN, "No transfer to ABOR");
	
}

void Session::onPwd()
{
	char text[1024] = {0};
	char dir[1024+1] = {0};
	getcwd(dir, 1024);
	sprintf(text, "\"%s\"", dir);

	ftp_reply(FTP_PWDOK, text);
}

void Session::onMkd()
{
	// 0777 & umask
	if (mkdir(arg_, 0777) < 0)
	{
		ftp_reply(FTP_FILEFAIL, "Create directory operation failed.");
		return;
	}
	
	char text[4096] = {0};
	if (arg_[0] == '/')
	{
		sprintf(text, "%s created", arg_);
	}
	else
	{
		char dir[4096+1] = {0};
		getcwd(dir, 4096);
		if (dir[strlen(dir)-1] == '/')
		{
			sprintf(text, "%s%s created", dir, arg_);
		}
		else
		{
			sprintf(text, "%s/%s created", dir, arg_);
		}
	}

	ftp_reply(FTP_MKDIROK, text);
}

void Session::onRmd()
{
	if (rmdir(arg_) < 0)
	{
		ftp_reply(FTP_FILEFAIL, "Remove directory operation failed.");
	}

	ftp_reply(FTP_RMDIROK, "Remove directory operation successful.");

}

void Session::onDele()
{
	if (unlink(arg_) < 0)
	{
		ftp_reply(FTP_FILEFAIL, "Delete operation failed.");
		return;
	}

	ftp_reply(FTP_DELEOK, "Delete operation successful.");
}

void Session::onRnfr()
{
	rnfr_name_ = (char *)malloc(strlen(arg_) + 1);
	memset(rnfr_name_, 0, strlen(arg_) + 1);
	strcpy(rnfr_name_, arg_);
	ftp_reply(FTP_RNFROK, "Ready for RNTO.");
}

void Session::onRnto()
{
	if (rnfr_name_ == NULL)
	{
		ftp_reply(FTP_NEEDRNFR, "RNFR required first.");
		return;
	}

	rename(rnfr_name_, arg_);

	ftp_reply(FTP_RENAMEOK, "Rename successful.");

	free(rnfr_name_);
	rnfr_name_= NULL;
}


void Session::onSite()
{
	// SITE CHMOD <perm> <file>
	// SITE UMASK [umask]
	// SITE HELP

	char cmd[100] = {0};
	char arg[100] = {0};

	strSplit(arg_, cmd, arg, ' ');
	if (strcmp(cmd, "CHMOD") == 0)
	{
		onSiteChmod(arg);
	}
	else if (strcmp(cmd, "UMASK") == 0)
	{
		onSiteUmask(arg);
	}
	else if (strcmp(cmd, "HELP") == 0)
	{
		ftp_reply(FTP_SITEHELP, "CHMOD UMASK HELP");
	}
	else
	{
		 ftp_reply(FTP_BADCMD, "Unknown SITE command.");
	}

}

void Session::onSyst()
{
	ftp_reply(FTP_SYSTOK, "UNIX Type: L8");
}

void Session::onFeat()
{
	ftp_lreply(FTP_FEAT, "Features:");
	writen(ctrlFd_, " EPRT\r\n", strlen(" EPRT\r\n"));
	writen(ctrlFd_, " EPSV\r\n", strlen(" EPSV\r\n"));
	writen(ctrlFd_, " MDTM\r\n", strlen(" MDTM\r\n"));
	writen(ctrlFd_, " PASV\r\n", strlen(" PASV\r\n"));
	writen(ctrlFd_, " REST STREAM\r\n", strlen(" REST STREAM\r\n"));
	writen(ctrlFd_, " SIZE\r\n", strlen(" SIZE\r\n"));
	writen(ctrlFd_, " TVFS\r\n", strlen(" TVFS\r\n"));
	writen(ctrlFd_, " UTF8\r\n", strlen(" UTF8\r\n"));
	ftp_reply(FTP_FEAT, "End");
}

void Session::onSize()
{
	//550 Could not get file size.

	struct stat buf;
	if (stat(arg_, &buf) < 0)
	{
		ftp_reply(FTP_FILEFAIL, "SIZE operation failed.");
		return;
	}

	if (!S_ISREG(buf.st_mode))
	{
		ftp_reply(FTP_FILEFAIL, "Could not get file size.");
		return;
	}

	char text[1024] = {0};
	sprintf(text, "%lld", (long long)buf.st_size);
	ftp_reply(FTP_SIZEOK, text);
}

void Session::onStat()
{
	ftp_lreply(FTP_STATOK, "FTP server status:");
	if (bw_upload_rate_max == 0)
	{
		char text[1024];
		sprintf(text,
			"     No session upload bandwidth limit\r\n");
		writen(ctrlFd_, text, strlen(text));
	}
	else if (bw_upload_rate_max > 0)
	{
		char text[1024];
		sprintf(text,
			"     Session upload bandwidth limit in byte/s is %u\r\n",
			bw_upload_rate_max);
		writen(ctrlFd_, text, strlen(text));
	}

	if (bw_download_rate_max == 0)
	{
		char text[1024];
		sprintf(text,
			"     No session download bandwidth limit\r\n");
		writen(ctrlFd_, text, strlen(text));
	}
	else if (bw_download_rate_max > 0)
	{
		char text[1024];
		sprintf(text,
			"     Session download bandwidth limit in byte/s is %u\r\n",
			bw_download_rate_max);
		writen(ctrlFd_, text, strlen(text));
	}

	char text[1024] = {0};
	sprintf(text,
		"     At session startup, client count was %u\r\n",
		num_clients);
	writen(ctrlFd_, text, strlen(text));
	
	ftp_reply(FTP_STATOK, "End of status");
}

void Session::onNoop()
{
	ftp_reply(FTP_NOOPOK, "NOOP ok.");

}

void Session::onHelp()
{
	ftp_lreply(FTP_HELP, "The following commands are recognized.");
	writen(ctrlFd_,
		" ABOR ACCT ALLO APPE CDUP CWD  DELE EPRT EPSV FEAT HELP LIST MDTM MKD\r\n",
		strlen(" ABOR ACCT ALLO APPE CDUP CWD  DELE EPRT EPSV FEAT HELP LIST MDTM MKD\r\n"));
	writen(ctrlFd_,
		" MODE NLST NOOP OPTS PASS PASV PORT PWD  QUIT REIN REST RETR RMD  RNFR\r\n",
		strlen(" MODE NLST NOOP OPTS PASS PASV PORT PWD  QUIT REIN REST RETR RMD  RNFR\r\n"));
	writen(ctrlFd_,
		" RNTO SITE SIZE SMNT STAT STOR STOU STRU SYST TYPE USER XCUP XCWD XMKD\r\n",
		strlen(" RNTO SITE SIZE SMNT STAT STOR STOU STRU SYST TYPE USER XCUP XCWD XMKD\r\n"));
	writen(ctrlFd_,
		" XPWD XRMD\r\n",
		strlen(" XPWD XRMD\r\n"));
	ftp_reply(FTP_HELP, "Help OK.");
}

void Session::onSiteChmod( char *chmod_arg)
{
	// SITE CHMOD <perm> <file>
	if (strlen(chmod_arg) == 0)
	{
		ftp_reply(FTP_BADCMD, "SITE CHMOD needs 2 arguments.");
		return;
	}

	char perm[100] = {0};
	char file[100] = {0};
	strSplit(chmod_arg , perm, file, ' ');
	if (strlen(file) == 0)
	{
		ftp_reply(FTP_BADCMD, "SITE CHMOD needs 2 arguments.");
		return;
	}

	unsigned int mode = strOctalToUint(perm);
	if (chmod(file, mode) < 0)
	{
		ftp_reply(FTP_CHMODOK, "SITE CHMOD command failed.");
	}
	else
	{
		ftp_reply(FTP_CHMODOK, "SITE CHMOD command ok.");
	}
}

void Session::onSiteUmask( char *umask_arg)
{
	// SITE UMASK [umask]
	if (strlen(umask_arg) == 0)
	{
		char text[1024] = {0};
		sprintf(text, "Your current UMASK is 0%o", g_cfg.local_umask);
		ftp_reply(FTP_UMASKOK, text);
	}
	else
	{
		unsigned int um = strOctalToUint(umask_arg);
		umask(um);
		char text[1024] = {0};
		sprintf(text, "UMASK set to 0%o", um);
		ftp_reply(FTP_UMASKOK, text);
	}
}


// nobody
void Session::innerGetDataFd()
{
	unsigned short port = (unsigned short)InGetInt(parentFd_);
	char ip[16] = {0};
	InRecvIp(parentFd_, ip, sizeof(ip));

	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = inet_addr(ip);

	int fd = tcp_client(20);
	if (fd == -1)
	{
		InSendResult(parentFd_, INNER_BAD);
		return;
	}
	if (connect_timeout(fd, &addr, g_cfg.connect_timeout) < 0)
	{
		close(fd);
		InSendResult(parentFd_, INNER_BAD);
		return;
	}

	InSendResult(parentFd_, INNER_OK);
	InSendFd(parentFd_, fd);
	close(fd);
}

void Session::innerPasvActive()
{
	int active;
	if (pasv_listen_fd_ != -1)
	{
		active = 1;
	}
	else
	{
		active = 0;
	}

	InGetInt(parentFd_, active);
}

void Session::innerPasvListen()
{
	char ip[16] = {0};
	getlocalip(ip);

	pasv_listen_fd_ = tcp_server(ip, 0);
	struct sockaddr_in addr;
	socklen_t addrlen = sizeof(addr);
	if (getsockname(pasv_listen_fd_, (struct sockaddr *)&addr, &addrlen) < 0)
	{
		log_exit("getsockname");
	}

	unsigned short port = ntohs(addr.sin_port);

	InGetInt(parentFd_, (int)port);
}

void Session::innerPasvAccept()
{
	int fd = accept_timeout(pasv_listen_fd_, NULL, g_cfg.accept_timeout);
	close(pasv_listen_fd_);
	pasv_listen_fd_ = -1;

	if (fd == -1)
	{
		InSendResult(parentFd_, INNER_BAD);
		return;
	}

	InSendResult(parentFd_, INNER_OK);
	InSendFd(parentFd_, fd);
	close(fd);
}


int capset(cap_user_header_t hdrp, const cap_user_data_t datap)
{
	return syscall(__NR_capset, hdrp, datap);
}

void minimize_privilege(void)
{
	struct passwd *pw = getpwnam("nobody");
	if (pw == NULL)
		return;

	if (setegid(pw->pw_gid) < 0)
		log_exit("setegid");
	if (seteuid(pw->pw_uid) < 0)
		log_exit("seteuid");


	struct __user_cap_header_struct cap_header;
	struct __user_cap_data_struct cap_data;

	memset(&cap_header, 0, sizeof(cap_header));
	memset(&cap_data, 0, sizeof(cap_data));

	cap_header.version = _LINUX_CAPABILITY_VERSION_1;
	cap_header.pid = 0;

	__u32 cap_mask = 0;
	cap_mask |= (1 << CAP_NET_BIND_SERVICE);

	cap_data.effective = cap_data.permitted = cap_mask;
	cap_data.inheritable = 0;

	capset(&cap_header, &cap_data);
}

