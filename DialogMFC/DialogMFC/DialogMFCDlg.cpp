
// DialogMFCDlg.cpp : 实现文件
//

#include "stdafx.h"
#include "DialogMFC.h"
#include "DialogMFCDlg.h"
#include "afxdialogex.h"
#include "source.h"


#ifdef _DEBUG
#define new DEBUG_NEW
#endif


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


// CDialogMFCDlg 对话框



CDialogMFCDlg::CDialogMFCDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(CDialogMFCDlg::IDD, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CDialogMFCDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, NET_LIST, net_list);
	DDX_Control(pDX, IDC_IPADDRESS2, search_ip_start);
	DDX_Control(pDX, IDC_IPADDRESS3, search_ip_end);
}

BEGIN_MESSAGE_MAP(CDialogMFCDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_ADD_ITEM, &CDialogMFCDlg::OnBnClickedAddItem)
	ON_BN_CLICKED(IDOK, &CDialogMFCDlg::OnBnClickedOk)
END_MESSAGE_MAP()


// CDialogMFCDlg 消息处理程序

BOOL CDialogMFCDlg::OnInitDialog()
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

	CRect rect;
	net_list.GetClientRect(&rect);

	net_list.SetExtendedStyle(net_list.GetExtendedStyle() | LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);

	net_list.InsertColumn(0, _T("ip地址"), LVCFMT_CENTER, rect.Width() / 3);
	net_list.InsertColumn(2, _T("主机名"), LVCFMT_CENTER, rect.Width() / 3);
	net_list.InsertColumn(4, _T("状态"), LVCFMT_CENTER, rect.Width() / 3);
	search_ip_start.SetAddress(192, 168, 1, 1);
	search_ip_end.SetAddress(192, 168, 255, 255);
	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CDialogMFCDlg::OnSysCommand(UINT nID, LPARAM lParam)
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

void CDialogMFCDlg::OnPaint()
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
HCURSOR CDialogMFCDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}






void CDialogMFCDlg::OnBnClickedAddItem()
{
	
	net_list.DeleteAllItems();
	itemCount = 0;
	/*net_list.InsertItem(itemCount, _T("表单项1"));
	net_list.SetItemText(itemCount, 1, _T("表单项子项1"));

	net_list.SetItemText(itemCount, 2, _T("表单项子项2"));

	itemCount++;
	
	UpdateData(FALSE);*/
	BYTE a1, a2, a3, a4;
	char buffer_1[30], buffer_2[30];
	search_ip_start.GetAddress(a1, a2, a3, a4);
	sprintf_s(buffer_1, "%d.%d.%d.%d", a1, a2, a3, a4);

	search_ip_end.GetAddress(a1, a2, a3, a4);
	sprintf_s(buffer_2, "%d.%d.%d.%d", a1, a2, a3, a4);

	std::string ip_start(buffer_1);
	std::string ip_end(buffer_2);

	std::vector<std::vector<std::string>> returnVector = GetNameAndIp(ip_start, ip_end);

	for (size_t i = 0; i < returnVector.size(); i++)
	{
		std::vector<std::string> vector_1 = returnVector.at(i);

		CString ip(vector_1.at(0).c_str());
		CString name(vector_1.at(1).c_str());

		net_list.InsertItem(itemCount, _T(""));
		net_list.SetItemText(itemCount, 0, ip);

		net_list.SetItemText(itemCount, 1, name);

		net_list.SetItemText(itemCount, 2, _T("在线"));

		itemCount++;
	}
	UpdateData(TRUE);
	// TODO:  在此添加控件通知处理程序代码
}


void CDialogMFCDlg::OnLbnSelchangeList1()
{
	// TODO:  在此添加控件通知处理程序代码
}


void CDialogMFCDlg::OnBnClickedOk()
{
	// TODO:  在此添加控件通知处理程序代码
	CDialogEx::OnOK();
}



