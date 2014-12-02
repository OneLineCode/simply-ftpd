#ifndef _SESSION_H_
#define _SESSION_H_

#include "common.h"

extern std::map<std::string, int> cmd_map;

typedef struct ftpcmd
{
	const char *cmd;
	//void (*cmd_handler)();
	int seq;
} ftpcmd_t;
extern ftpcmd_t cmd_array[FTP_MAX_CMD]; //否则是不完全类型


class Session
{
public:
	Session(int conn, unsigned int  ip);
	~Session();
	void start();
	void checkLimits();
	void runServiceProcess();
	void runNobodyProcess();

	int getCtrlFd();
	int getDataFd();
	bool getTransferring();
	void setTransferring(bool isTransferring);
	void setAbor(bool abor);


	void ftp_reply(int status, const char *text);
	static void ftp_reply(int ctrlFd, int status, const char *text);
	void ftp_lreply(int status, const char *text);

	static void handleAlarmTimeout(int sig);
	static void handleSigalrm(int sig);
	static void handleSigurg(int sig);
	void startSessionAlarm(void);
	void startDataAlarm(void);

	void checkAbor();

	int list(int detail);
	void limitRate(int bytes_transfered, int is_upload);
	void upload(int is_append);

	int getPortFd();
	int getPasvFd();
	int getTransferFd();
	int portActive();
	int pasvActive();

	void onUser();
	void onPass();
	void onCwd();
	void onCdUp();
	void onQuit();
	void onPort();
	void onPasv();
	void onType();

	void onRetr();
	void onStor();
	void onAppe();
	void onList();
	void onNlist();
	void onRest();
	void onAbor();
	void onPwd();
	void onMkd();
	void onRmd();
	void onDele();
	void onRnfr();
	void onRnto();
	void onSite();
	void onSyst();
	void onFeat();
	void onSize();
	void onStat();
	void onNoop();
	void onHelp();


	void onSiteChmod(char *chmod_arg);
	void onSiteUmask(char *umask_arg);


	// nobody进程
	void innerGetDataFd();
	void innerPasvActive();
	void innerPasvListen();
	void innerPasvAccept();
private:

	// 控制连接
	uid_t uid_;
	int ctrlFd_;
	char cmdline_[MAX_COMMAND_LINE];
	char cmd_[MAX_COMMAND];
	char arg_[MAX_ARG];

	// 限速
	unsigned int bw_upload_rate_max;
	unsigned int bw_download_rate_max;
	long bw_transfer_start_sec;
	long bw_transfer_start_usec;

	// 数据连接
	struct sockaddr_in *portAddr_;
	int pasv_listen_fd_;
	int dataFd_;
	//bool data_process_;// 数据传输中
	bool isTransferring_;// 数据传输中

	// 父子进程通道
	int parentFd_;
	int childFd_;

	// FTP协议状态
	int is_ascii_;
	long long restart_pos_;
	char *rnfr_name_;
	//int abor_received_;
	bool abor_;

	// 本Session连接数限制
	static unsigned int num_clients;
	//
	unsigned int ip_;
};

/*
typedef struct session
{
	// 控制连接
	uid_t uid;
	int ctrl_fd;
	char cmdline[MAX_COMMAND_LINE];
	char cmd[MAX_COMMAND];
	char arg[MAX_ARG];

	// 数据连接
	struct sockaddr_in *port_addr;
	int pasv_listen_fd;
	int data_fd;
	int data_process;

	// 限速
	unsigned int bw_upload_rate_max;
	unsigned int bw_download_rate_max;
	long bw_transfer_start_sec;
	long bw_transfer_start_usec;


	// 父子进程通道
	int parent_fd;
	int child_fd;

	// FTP协议状态
	int is_ascii;
	long long restart_pos;
	char *rnfr_name;
	int abor_received;

	// 连接数限制
	unsigned int num_clients;
	unsigned int num_this_ip;
} session_t;
*/

extern Session* g_SessPtr; // for signal

int capset(cap_user_header_t hdrp, const cap_user_data_t datap);

void minimize_privilege(void);

#endif /* _SESSION_H_ */

