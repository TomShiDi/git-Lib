
// DialogMFCDlg.h : 头文件
//

#pragma once
#include "afxwin.h"
#include "afxcmn.h"


// CDialogMFCDlg 对话框
class CDialogMFCDlg : public CDialogEx
{
// 构造
public:
	CDialogMFCDlg(CWnd* pParent = NULL);	// 标准构造函数

// 对话框数据
	enum { IDD = IDD_DIALOGMFC_DIALOG };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持


// 实现
protected:
	HICON m_hIcon;
	int itemCount = 0;
	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	
	afx_msg void OnBnClickedAddItem();
	afx_msg void OnLbnSelchangeList1();
	afx_msg void OnBnClickedOk();
	CListCtrl net_list;
	CIPAddressCtrl search_ip_start;
	CIPAddressCtrl search_ip_end;
};
