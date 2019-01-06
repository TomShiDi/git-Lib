
// DialogMFCDlg.h : ͷ�ļ�
//

#pragma once
#include "afxwin.h"
#include "afxcmn.h"


// CDialogMFCDlg �Ի���
class CDialogMFCDlg : public CDialogEx
{
// ����
public:
	CDialogMFCDlg(CWnd* pParent = NULL);	// ��׼���캯��

// �Ի�������
	enum { IDD = IDD_DIALOGMFC_DIALOG };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV ֧��


// ʵ��
protected:
	HICON m_hIcon;
	int itemCount = 0;
	// ���ɵ���Ϣӳ�亯��
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
