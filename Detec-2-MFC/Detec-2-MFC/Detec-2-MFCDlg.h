
// Detec-2-MFCDlg.h : 头文件
//

#pragma once
#include "afxcmn.h"
#include "resource.h"



// CDetec2MFCDlg 对话框
class CDetec2MFCDlg : public CDialogEx
{
// 构造
public:
	CDetec2MFCDlg(CWnd* pParent = NULL);	// 标准构造函数

// 对话框数据
	enum { IDD = IDD_DETEC2MFC_DIALOG };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持


// 实现
protected:
	HICON m_hIcon;

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
	
public:
	CListCtrl m_detec_info_list;
	int itemCount;

	BOOL isRunning = FALSE;
	afx_msg void OnBnClickedStart();
	
	void output(PIP_ADAPTER_INFO pIpAdapterInfo);

	void GetSelfMac(char* pDevName);

	static UINT __cdecl recvArpPacket(LPVOID params);

	static unsigned char *BuildArpPacket(unsigned char *source_mac, unsigned long srcIP, unsigned long destIP);

	static UINT __cdecl sendArpPacket(LPVOID params);

	void start_detect();
	afx_msg void OnBnClickedEnd();
	CIPAddressCtrl m_ip_sender;
	CIPAddressCtrl m_ip_dest;
};
