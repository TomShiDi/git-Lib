
// DialogMFCDlg.cpp : ʵ���ļ�
//

#include "stdafx.h"
#include "DialogMFC.h"
#include "DialogMFCDlg.h"
#include "afxdialogex.h"
#include "source.h"


#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// ����Ӧ�ó��򡰹��ڡ��˵���� CAboutDlg �Ի���

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// �Ի�������
	enum { IDD = IDD_ABOUTBOX };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV ֧��

// ʵ��
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


// CDialogMFCDlg �Ի���



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


// CDialogMFCDlg ��Ϣ�������

BOOL CDialogMFCDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// ��������...���˵�����ӵ�ϵͳ�˵��С�

	// IDM_ABOUTBOX ������ϵͳ���Χ�ڡ�
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

	// ���ô˶Ի����ͼ�ꡣ  ��Ӧ�ó��������ڲ��ǶԻ���ʱ����ܽ��Զ�
	//  ִ�д˲���
	SetIcon(m_hIcon, TRUE);			// ���ô�ͼ��
	SetIcon(m_hIcon, FALSE);		// ����Сͼ��

	// TODO:  �ڴ���Ӷ���ĳ�ʼ������

	CRect rect;
	net_list.GetClientRect(&rect);

	net_list.SetExtendedStyle(net_list.GetExtendedStyle() | LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);

	net_list.InsertColumn(0, _T("ip��ַ"), LVCFMT_CENTER, rect.Width() / 3);
	net_list.InsertColumn(2, _T("������"), LVCFMT_CENTER, rect.Width() / 3);
	net_list.InsertColumn(4, _T("״̬"), LVCFMT_CENTER, rect.Width() / 3);
	search_ip_start.SetAddress(192, 168, 1, 1);
	search_ip_end.SetAddress(192, 168, 255, 255);
	return TRUE;  // ���ǽ��������õ��ؼ������򷵻� TRUE
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

// �����Ի��������С����ť������Ҫ����Ĵ���
//  �����Ƹ�ͼ�ꡣ  ����ʹ���ĵ�/��ͼģ�͵� MFC Ӧ�ó���
//  �⽫�ɿ���Զ���ɡ�

void CDialogMFCDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // ���ڻ��Ƶ��豸������

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// ʹͼ���ڹ����������о���
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// ����ͼ��
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//���û��϶���С������ʱϵͳ���ô˺���ȡ�ù��
//��ʾ��
HCURSOR CDialogMFCDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}






void CDialogMFCDlg::OnBnClickedAddItem()
{
	
	net_list.DeleteAllItems();
	itemCount = 0;
	/*net_list.InsertItem(itemCount, _T("����1"));
	net_list.SetItemText(itemCount, 1, _T("��������1"));

	net_list.SetItemText(itemCount, 2, _T("��������2"));

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

		net_list.SetItemText(itemCount, 2, _T("����"));

		itemCount++;
	}
	UpdateData(TRUE);
	// TODO:  �ڴ���ӿؼ�֪ͨ����������
}


void CDialogMFCDlg::OnLbnSelchangeList1()
{
	// TODO:  �ڴ���ӿؼ�֪ͨ����������
}


void CDialogMFCDlg::OnBnClickedOk()
{
	// TODO:  �ڴ���ӿؼ�֪ͨ����������
	CDialogEx::OnOK();
}



