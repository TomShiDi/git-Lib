
// Detec-2-MFCDlg.cpp : 实现文件
//

#include "stdafx.h"
#include "Detec-2-MFC.h"
#include "Detec-2-MFCDlg.h"
#include "afxdialogex.h"

#include "source.h"


#include<string>
#include<iostream>
#include<pcap.h>
#include <WinSock2.h>
#include <Iphlpapi.h>
#include<atlstr.h>

#include "Detec-2-MFCDlg.h"
#include<vector>
#include<Packet32.h>
#include<stdlib.h>
#include<thread>
#include<conio.h>

#pragma comment(lib,"mpr.lib")
#pragma comment(lib,"Iphlpapi.lib")
#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"Packet.lib")

#pragma pack(push) // 保持对齐方式
#pragma pack(1) // 设定1字节对齐


#ifdef _DEBUG
#define new DEBUG_NEW
#endif


//arp数据包
struct arp_head
{
	unsigned short hardware_type;//硬件类型
	unsigned short protocol_type;//协议类型
	unsigned char add_len;//硬件地址长度
	unsigned char pro_len;//协议地址长度
	unsigned short option;//操作类型，arp请求与应答，rarp请求与应答
	unsigned char sour_addr[6];//源MAC
	unsigned long sour_ip;//源IP
	unsigned char dest_addr[6];//目的MAC
	unsigned long dest_ip;//目的IP

};

struct ethernet_head
{
	unsigned char dest_mac[6];//目的MAC地址
	unsigned char source_mac[6];//源MAC地址
	unsigned short eh_type;//帧类型
};


//发送的数据包
struct arp_packet
{
	ethernet_head eth;//以太网首部
	arp_head arp;//arp包
	unsigned char padding[18];//填充数据
};


char packet_filter_1[] = "ether proto \\arp";

pcap_if_t *alldevs = NULL;//全部网卡列表 
pcap_if_t *d = NULL, *ds = NULL;//一个网卡 
//int inum;//用户选择的网卡序号 
//extern int i = 0;//循环变量 
pcap_t *adhandle;//一个pcap实例 
char errbuf[256]; //错误缓冲区 

unsigned char *packet;//ARP包 
unsigned long sourceIP;//要伪装成的IP地址 
unsigned long destIP;
pcap_addr_t *pAddr;//网卡地址 
unsigned long ip;//IP地址 
unsigned long netmask;//子网掩码 
struct in_addr net_ip_address;//网卡IP信息,在pcap.h里面有定义  
struct in_addr net_mask_address;
char *net_ip_string;
char *net_mask_string;


struct bpf_program fcode;


int result;
struct pcap_pkthdr * header;
const u_char * pkt_data;
struct in_addr temp;

BYTE mac[6];


///函数作用,输出网卡信息


// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

	// 对话框数据
	enum { IDD = IDD_ABOUTBOX };

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

	// 实现
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(CAboutDlg::IDD)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CDetec2MFCDlg 对话框



CDetec2MFCDlg::CDetec2MFCDlg(CWnd* pParent /*=NULL*/)
: CDialogEx(CDetec2MFCDlg::IDD, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CDetec2MFCDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, DETEC_INFO, m_detec_info_list);
	DDX_Control(pDX, IP_SENDER, m_ip_sender);
	DDX_Control(pDX, IP_DEST, m_ip_dest);
}

BEGIN_MESSAGE_MAP(CDetec2MFCDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(BTN_START, &CDetec2MFCDlg::OnBnClickedStart)
	ON_BN_CLICKED(BTN_END, &CDetec2MFCDlg::OnBnClickedEnd)
END_MESSAGE_MAP()


// CDetec2MFCDlg 消息处理程序

BOOL CDetec2MFCDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO:  在此添加额外的初始化代码

	m_ip_sender.SetAddress(0, 0, 0, 0);
	m_ip_dest.SetAddress(0, 0, 0, 0);

	CDetec2MFCDlg::itemCount = 0;
	CRect rect;
	m_detec_info_list.GetClientRect(&rect);

	m_detec_info_list.SetExtendedStyle(m_detec_info_list.GetExtendedStyle() | LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);

	m_detec_info_list.InsertColumn(0, _T("源ip地址"), LVCFMT_CENTER, rect.Width() / 5);
	m_detec_info_list.InsertColumn(2, _T("目的ip地址"), LVCFMT_CENTER, rect.Width() / 5);
	m_detec_info_list.InsertColumn(4, _T("源mac地址"), LVCFMT_CENTER, rect.Width() / 5);
	m_detec_info_list.InsertColumn(6, _T("目的mac地址"), LVCFMT_CENTER, rect.Width() / 5);
	m_detec_info_list.InsertColumn(8, _T("包类型"), LVCFMT_CENTER, rect.Width() / 5);

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CDetec2MFCDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CDetec2MFCDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CDetec2MFCDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}



void SplitString(const std::string &srcString, std::vector<std::string> &resultVector, const std::string &pattern)
{
	std::string::size_type pos2 = srcString.find(pattern);
	std::string::size_type pos1 = 0;
	while (std::string::npos != pos2)
	{
		resultVector.push_back(srcString.substr(pos1, pos2 - pos1));
		pos1 = pos2 + pattern.size();
		pos2 = srcString.find(pattern, pos1);
	}
	if (pos1 != srcString.length())
	{
		resultVector.push_back(srcString.substr(pos1));
	}
}


unsigned long str_ip_to_num(std::string ipString)
{
	std::vector<std::string> resultVector;
	SplitString(ipString, resultVector, ".");
	unsigned long sum = 0;
	unsigned long t = 1;
	for (size_t i = 0; i < resultVector.size(); i++)
	{
		t = 1;
		int s = atoi(resultVector.at(i).c_str());
		for (size_t j = 3 - i; j > 0; j--)
		{
			t = t * 256;
		}
		sum = sum + s * t;
	}

	return sum;
}


void CDetec2MFCDlg::OnBnClickedStart()
{
	this->isRunning = TRUE;
	start_detect();
	Sleep(200);

	//CWinThread *thread_send = AfxBeginThread(sendArpPacket, (LPVOID)this);

	CWinThread *thread_recv = AfxBeginThread(recvArpPacket, (LPVOID)this);

	// TODO:  在此添加控件通知处理程序代码
}


///函数作用,输出网卡信息
void CDetec2MFCDlg::output(PIP_ADAPTER_INFO pIpAdapterInfo)
{
	//可能有多网卡,因此通过循环去判断
	while (pIpAdapterInfo)
	{
		IP_ADDR_STRING *pIpAddrString = &(pIpAdapterInfo->IpAddressList);
		if (!strcmp(pIpAddrString->IpAddress.String, "10.1.18.24"))
		{
			std::cout << "网卡名称：" << pIpAdapterInfo->AdapterName << std::endl;
			std::cout << "网卡描述：" << pIpAdapterInfo->Description << std::endl;
			std::cout << "网卡MAC地址：";

			for (UINT i = 0; i < pIpAdapterInfo->AddressLength; i++)
			if (i == pIpAdapterInfo->AddressLength - 1)
			{
				mac[i] = pIpAdapterInfo->Address[i];
				printf("%02x\n", pIpAdapterInfo->Address[i]);
			}
			else
			{
				mac[i] = pIpAdapterInfo->Address[i];
				printf("%02x-", pIpAdapterInfo->Address[i]);

			}

			//std::cout << "网卡IP地址如下：" << std::endl;
			////可能网卡有多IP,因此通过循环去判断

			//do
			//{
			//	std::cout << pIpAddrString->IpAddress.String << std::endl;
			//	pIpAddrString = pIpAddrString->Next;
			//} while (pIpAddrString);
		}
		pIpAdapterInfo = pIpAdapterInfo->Next;
		std::cout << "*****************************************************" << std::endl;
	}
}


void CDetec2MFCDlg::GetSelfMac(char* pDevName)
{

	//PIP_ADAPTER_INFO结构体指针存储本机网卡信息
	PIP_ADAPTER_INFO pIpAdapterInfo = new IP_ADAPTER_INFO();
	//得到结构体大小,用于GetAdaptersInfo参数
	unsigned long stSize = sizeof(IP_ADAPTER_INFO);
	//调用GetAdaptersInfo函数,填充pIpAdapterInfo指针变量;其中stSize参数既是一个输入量也是一个输出量
	int nRel = GetAdaptersInfo(pIpAdapterInfo, &stSize);
	if (ERROR_BUFFER_OVERFLOW == nRel)
	{
		//如果函数返回的是ERROR_BUFFER_OVERFLOW
		//则说明GetAdaptersInfo参数传递的内存空间不够,同时其传出stSize,表示需要的空间大小
		//这也是说明为什么stSize既是一个输入量也是一个输出量
		//释放原来的内存空间
		delete pIpAdapterInfo;
		//重新申请内存空间用来存储所有网卡信息
		pIpAdapterInfo = (PIP_ADAPTER_INFO)new BYTE[stSize];
		//再次调用GetAdaptersInfo函数,填充pIpAdapterInfo指针变量
		nRel = GetAdaptersInfo(pIpAdapterInfo, &stSize);
	}
	if (ERROR_SUCCESS == nRel)
	{
		//输出网卡信息
		output(pIpAdapterInfo);
	}
	//释放内存空间
	if (pIpAdapterInfo)
	{
		delete pIpAdapterInfo;
	}

}




UINT __cdecl CDetec2MFCDlg::recvArpPacket(LPVOID params)
{
	/*if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
	std::cout << "Error in pcap_findalldevs: " << errbuf << std::endl;;
	exit(1);
	}*/

	BYTE a1, a2, a3, a4;
	char buffer[64];
	long ip_start, ip_end;
	std::string ipstartstr, ipendstr;
	std::cout << "进入recv" << std::endl;
	CDetec2MFCDlg *pHandler = (CDetec2MFCDlg *)params;

	pHandler->m_ip_sender.GetAddress(a1, a2, a3, a4);
	sprintf_s(buffer, "%d.%d.%d.%d", a1, a2, a3, a4);
	ipstartstr.assign(buffer);
	ip_start = str_ip_to_num(ipstartstr);

	memset(buffer, 0, 64);

	pHandler->m_ip_dest.GetAddress(a1, a2, a3, a4);
	sprintf_s(buffer, "%d.%d.%d.%d", a1, a2, a3, a4);
	ipendstr.assign(buffer);
	ip_end = str_ip_to_num(ipendstr);


	d = alldevs;
	if ((adhandle = pcap_open_live(d->name, 65536, 1, 3000, errbuf)) == NULL)
	{
		/*打开失败*/
		std::cout << "打开失败." << d->name << "不被winpcap支持" << std::endl;
		/* 释放设备列表 */
		pcap_freealldevs(alldevs);
		return -1;
	}

	pAddr = d->addresses;
	netmask = ((struct sockaddr_in*)pAddr->netmask)->sin_addr.S_un.S_addr;

	if (pcap_compile(adhandle, &fcode, packet_filter_1, 1, netmask) < 0)
	{
		printf("\nUnable to compile the packet filter.Check the syntax.\n");
		pcap_freealldevs(alldevs);
		return -1;
	}


	if (pcap_setfilter(adhandle, &fcode) < 0)
	{
		//printf("\nError setting the filter.\n");
		pcap_freealldevs(alldevs);
		return -1;
	}

	while ((result = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0)
	{

		//循环解析ARP数据包

		if (result == 0)//返回0表示超时
		{
			//std::cout << "未接收到arp数据包，该IP可能不处于活动状态" << std::endl;
			continue;
		}
		//std::cout << "有数据" << std::endl;
		arp_packet* arph = (arp_packet *)pkt_data;

		//arph->arp.sour_ip == inet_addr("192.168.1.101") && arph->arp.dest_ip == inet_addr("192.168.1.1")

		if (pHandler->isRunning)
		{
			char buffer[64];

			temp.S_un.S_addr = arph->arp.sour_ip;
			CString srcIp(inet_ntoa(temp));
			temp.S_un.S_addr = arph->arp.dest_ip;
			CString destinationIp(inet_ntoa(temp));

			in_addr startTemp, endTemp;

			startTemp.S_un.S_addr = arph->arp.sour_ip;
			endTemp.S_un.S_addr = arph->arp.dest_ip;

			if (ip_start != 0 || ip_end != 0)
			{
				if (ip_start != 0 && ip_end == 0)
				{
					if (ip_start == str_ip_to_num(inet_ntoa(startTemp)))
					{
						sprintf_s(buffer, "源MAC：%.2x-%.2x - %.2x -%.2x -%.2x -%.2x", arph->arp.sour_addr[0], arph->arp.sour_addr[1],
							arph->arp.sour_addr[2], arph->arp.sour_addr[3], arph->arp.sour_addr[4], arph->arp.sour_addr[5]);

						CString srcMac(buffer);

						ZeroMemory(buffer, 64);

						sprintf_s(buffer, "目的MAC：%.2x-%.2x - %.2x -%.2x -%.2x -%.2x", arph->arp.dest_addr[0], arph->arp.dest_addr[1],
							arph->arp.dest_addr[2], arph->arp.dest_addr[3], arph->arp.dest_addr[4], arph->arp.dest_addr[5]);

						CString destMac(buffer);

						ZeroMemory(buffer, 64);

						sprintf_s(buffer, "%d", arph->arp.option);

						CString option(buffer);

						//std::cout << "包类型：" << arph->arp.option << std::endl;



						pHandler->m_detec_info_list.InsertItem(pHandler->itemCount, _T(""));
						pHandler->m_detec_info_list.SetItemText(pHandler->itemCount, 0, srcIp);
						pHandler->m_detec_info_list.SetItemText(pHandler->itemCount, 1, destinationIp);
						pHandler->m_detec_info_list.SetItemText(pHandler->itemCount, 2, srcMac);
						pHandler->m_detec_info_list.SetItemText(pHandler->itemCount, 3, destMac);
						pHandler->m_detec_info_list.SetItemText(pHandler->itemCount, 4, option);

						pHandler->itemCount = pHandler->itemCount + 1;
						continue;
					}
					else
					{
						continue;
					}

					if (ip_start == 0 && ip_end != 0)
					{
						if (ip_end == str_ip_to_num(inet_ntoa(endTemp)))
						{
							sprintf_s(buffer, "源MAC：%.2x-%.2x - %.2x -%.2x -%.2x -%.2x", arph->arp.sour_addr[0], arph->arp.sour_addr[1],
								arph->arp.sour_addr[2], arph->arp.sour_addr[3], arph->arp.sour_addr[4], arph->arp.sour_addr[5]);

							CString srcMac(buffer);

							ZeroMemory(buffer, 64);

							sprintf_s(buffer, "目的MAC：%.2x-%.2x - %.2x -%.2x -%.2x -%.2x", arph->arp.dest_addr[0], arph->arp.dest_addr[1],
								arph->arp.dest_addr[2], arph->arp.dest_addr[3], arph->arp.dest_addr[4], arph->arp.dest_addr[5]);

							CString destMac(buffer);

							ZeroMemory(buffer, 64);

							sprintf_s(buffer, "%d", arph->arp.option);

							CString option(buffer);

							//std::cout << "包类型：" << arph->arp.option << std::endl;



							pHandler->m_detec_info_list.InsertItem(pHandler->itemCount, _T(""));
							pHandler->m_detec_info_list.SetItemText(pHandler->itemCount, 0, srcIp);
							pHandler->m_detec_info_list.SetItemText(pHandler->itemCount, 1, destinationIp);
							pHandler->m_detec_info_list.SetItemText(pHandler->itemCount, 2, srcMac);
							pHandler->m_detec_info_list.SetItemText(pHandler->itemCount, 3, destMac);
							pHandler->m_detec_info_list.SetItemText(pHandler->itemCount, 4, option);

							pHandler->itemCount = pHandler->itemCount + 1;
							continue;
						}
						else
						{
							continue;
						}


						if (ip_start != 0 && ip_end != 0)
						{
							if (ip_start == str_ip_to_num(inet_ntoa(startTemp)) && ip_end == str_ip_to_num(inet_ntoa(endTemp)))
							{
								sprintf_s(buffer, "源MAC：%.2x-%.2x - %.2x -%.2x -%.2x -%.2x", arph->arp.sour_addr[0], arph->arp.sour_addr[1],
									arph->arp.sour_addr[2], arph->arp.sour_addr[3], arph->arp.sour_addr[4], arph->arp.sour_addr[5]);

								CString srcMac(buffer);

								ZeroMemory(buffer, 64);

								sprintf_s(buffer, "目的MAC：%.2x-%.2x - %.2x -%.2x -%.2x -%.2x", arph->arp.dest_addr[0], arph->arp.dest_addr[1],
									arph->arp.dest_addr[2], arph->arp.dest_addr[3], arph->arp.dest_addr[4], arph->arp.dest_addr[5]);

								CString destMac(buffer);

								ZeroMemory(buffer, 64);

								sprintf_s(buffer, "%d", arph->arp.option);

								CString option(buffer);

								//std::cout << "包类型：" << arph->arp.option << std::endl;



								pHandler->m_detec_info_list.InsertItem(pHandler->itemCount, _T(""));
								pHandler->m_detec_info_list.SetItemText(pHandler->itemCount, 0, srcIp);
								pHandler->m_detec_info_list.SetItemText(pHandler->itemCount, 1, destinationIp);
								pHandler->m_detec_info_list.SetItemText(pHandler->itemCount, 2, srcMac);
								pHandler->m_detec_info_list.SetItemText(pHandler->itemCount, 3, destMac);
								pHandler->m_detec_info_list.SetItemText(pHandler->itemCount, 4, option);

								pHandler->itemCount = pHandler->itemCount + 1;
								continue;
							}
							else
							{
								continue;
							}
						}
					}
				}
			}


			//std::cout << "源IP：" << inet_ntoa(temp) << std::endl;

			//std::cout << "目的IP:" << inet_ntoa(temp) << std::endl;


			sprintf_s(buffer, "源MAC：%.2x-%.2x - %.2x -%.2x -%.2x -%.2x", arph->arp.sour_addr[0], arph->arp.sour_addr[1],
				arph->arp.sour_addr[2], arph->arp.sour_addr[3], arph->arp.sour_addr[4], arph->arp.sour_addr[5]);

			CString srcMac(buffer);

			ZeroMemory(buffer, 64);

			sprintf_s(buffer, "目的MAC：%.2x-%.2x - %.2x -%.2x -%.2x -%.2x", arph->arp.dest_addr[0], arph->arp.dest_addr[1],
				arph->arp.dest_addr[2], arph->arp.dest_addr[3], arph->arp.dest_addr[4], arph->arp.dest_addr[5]);

			CString destMac(buffer);

			ZeroMemory(buffer, 64);

			sprintf_s(buffer, "%d", arph->arp.option);

			CString option(buffer);

			//std::cout << "包类型：" << arph->arp.option << std::endl;



			pHandler->m_detec_info_list.InsertItem(pHandler->itemCount, _T(""));
			pHandler->m_detec_info_list.SetItemText(pHandler->itemCount, 0, srcIp);
			pHandler->m_detec_info_list.SetItemText(pHandler->itemCount, 1, destinationIp);
			pHandler->m_detec_info_list.SetItemText(pHandler->itemCount, 2, srcMac);
			pHandler->m_detec_info_list.SetItemText(pHandler->itemCount, 3, destMac);
			pHandler->m_detec_info_list.SetItemText(pHandler->itemCount, 4, option);

			pHandler->itemCount = pHandler->itemCount + 1;
			Sleep(20);
		}
	}
	return 0;

}


unsigned char *CDetec2MFCDlg::BuildArpPacket(unsigned char *source_mac, unsigned long srcIP, unsigned long destIP)
{
	static struct arp_packet packet;


	//目的MAC地址为广播地址，FF-FF-FF-FF-FF-FF 
	memset(packet.eth.dest_mac, 0xFF, 6);

	//源MAC地址 
	memcpy(packet.eth.source_mac, source_mac, 6);


	//上层协议为ARP协议，0x0806 
	packet.eth.eh_type = htons(0x0806);

	//硬件类型，Ethernet是0x0001 
	packet.arp.hardware_type = htons(0x0001);

	//上层协议类型，IP为0x0800 
	packet.arp.protocol_type = htons(0x0800);

	//硬件地址长度：MAC地址长度为0x06 
	packet.arp.add_len = 6;

	//协议地址长度：IP地址长度为0x04 
	packet.arp.pro_len = 4;

	//操作：ARP请求为1 
	packet.arp.option = htons(1);

	//源MAC地址 
	memcpy(packet.arp.sour_addr, source_mac, 6);

	//源IP地址 
	packet.arp.sour_ip = srcIP;

	//目的MAC地址，填充0 
	memset(packet.arp.dest_addr, 0, 6);

	//目的IP地址 
	packet.arp.dest_ip = destIP;

	//填充数据，18个字节
	ZeroMemory(packet.padding, 18);


	return (unsigned char*)&packet;
}




UINT __cdecl CDetec2MFCDlg::sendArpPacket(LPVOID params)
{
	/*if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
	std::cout << "Error in pcap_findalldevs:" << errbuf << std::endl;
	return -1;
	}*/
	int i = 0;
	pcap_addr_t *pAddr;
	for (ds = alldevs; ds; ds = ds->next)
	{
		std::cout << ++i;
		if (ds->description)
		{
			std::cout << "." << ds->description << ";" << inet_ntoa(((struct sockaddr_in *)ds->addresses->addr)->sin_addr) << std::endl;
		}
		else
			std::cout << ".No description available" << std::endl;
	}
	//如果没有网卡
	if (i == 0)
	{
		std::cout << "\nNo interfaces found! Make sure WinPcapis installed.\n" << std::endl;
		return -1;
	}

	ds = alldevs;

	if ((adhandle = pcap_open_live(ds->name, 65536, 0, 1000, errbuf)) == NULL)
	{
		std::cout << "Unable to open the adapter." << ds->name << "errbuf:  " << errbuf << std::endl;
		return -1;
	}

	pAddr = ds->addresses;
	ip = ((struct sockaddr_in *)pAddr->addr)->sin_addr.s_addr;


	char buffer[128];
	sprintf_s(buffer, "%02x-%02x-%02x-%02x-%02x-%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	std::cout << buffer << std::endl;

	sourceIP = ip;
	for (int j = 5; j > 0;)
	{
		for (UINT i = 0; i < 100; i++)
		{
			char buffer[32];
			//std::string str = "192.168.1.1";

			sprintf_s(buffer, "10.1.18.%d", i);

			destIP = inet_addr(buffer);
			std::cout << buffer << std::endl;

			//destIP = inet_addr("192.168.1.100");//我要探测的IP


			packet = BuildArpPacket(mac, sourceIP, destIP);
			//printf("%x", packet);
			if (pcap_sendpacket(adhandle, packet, 60) == -1)
			{
				std::cout << "pcap_sendpacket error" << std::endl;
			}
			//std::cout << "本地ip:  " << inet_ntoa(((struct sockaddr_in *)pAddr->addr)->sin_addr) << std::endl;
			Sleep(200);
		}

	}
	//pcap_close(adhandle);

	/*destIP = inet_addr("192.168.1.1");

	packet = BuildArpPacket(mac, sourceIP, destIP);

	while (true)
	{
	if (pcap_sendpacket(adhandle, packet, 100) == -1)
	{
	std::cout << "pcap_sendpacket error" << std::endl;
	}
	Sleep(5000);
	}*/
	return 0;
}

void CDetec2MFCDlg::start_detect()
{
	if (alldevs == NULL)
	{
		if (pcap_findalldevs(&alldevs, errbuf) == -1)
		{
			std::cout << "Error in pcap_findalldevs:" << errbuf << std::endl;
			return;
		}
	}

	GetSelfMac(alldevs->name);

	/*std::thread thread_send(sendArpPacket);
	Sleep(1000);
	std::thread thread_recv(recvArpPacket, cDetec2MFCDlg);*/
	/*while (true)
	{
	if (_kbhit())
	{
	if (_getch() == '\r')
	{
	break;
	}
	}
	}*/

}







void CDetec2MFCDlg::OnBnClickedEnd()
{
	// TODO:  在此添加控件通知处理程序代码
	this->isRunning = FALSE;
}
