
// Detec-2-MFC.h : PROJECT_NAME Ӧ�ó������ͷ�ļ�
//

#pragma once

#ifndef __AFXWIN_H__
	#error "�ڰ������ļ�֮ǰ������stdafx.h�������� PCH �ļ�"
#endif

#include "resource.h"		// ������


// CDetec2MFCApp: 
// �йش����ʵ�֣������ Detec-2-MFC.cpp
//

class CDetec2MFCApp : public CWinApp
{
public:
	CDetec2MFCApp();

// ��д
public:
	virtual BOOL InitInstance();

// ʵ��

	DECLARE_MESSAGE_MAP()
};

extern CDetec2MFCApp theApp;