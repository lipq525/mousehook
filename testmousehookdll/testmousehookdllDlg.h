
// testmousehookdllDlg.h: 头文件
//
#pragma once
#include "afxwin.h"
#include "MyMouseHook.h"



#define WM_HOOK_TEXTOUT (WM_USER+101)

typedef struct _RemoteParam
{
    DWORD dwTextOutA;
    DWORD dwTextOutW;
    DWORD dwExtTextOutA;
    DWORD dwExtTextOutW;
    DWORD dwPostMessage;
    DWORD dwSendMessage;
    DWORD dwGetCurrentProcess;
    DWORD dwWriteProcessMemory;
    DWORD dwMessageBox;
    unsigned char oldCode[10];
    unsigned char newCode[10];
    DWORD FunAddr;
    BOOL bHookAlready; //是否挂上API钩子
    HWND hwnd; //安放钩子的那个窗口句柄
    LPCWSTR lpString; //专门用于保存TextOut的字符串地址
    LPCSTR lpcstring;
    wchar_t info[260];
} RemoteParam, * pRemoteParam;



// CtestmousehookdllDlg 对话框
class CtestmousehookdllDlg : public CDialogEx
{
// 构造
public:
	CtestmousehookdllDlg(CWnd* pParent = nullptr);	// 标准构造函数

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_TESTMOUSEHOOKDLL_DIALOG };
#endif

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
    CMyMouseHook m_mouse_hook;
    CEdit m_edit;
    BOOL is_quci_open;
    CString m_edit_str;
    HWND m_hwnd_hook;
    BOOL bHookAlready; //是否挂钩子的标志
    unsigned char oldcode[10]; //用来保存API的原始代码
    unsigned char newcode[10]; //用来保存API修改后的代码
    DWORD dwFunAddr;
    DWORD dwPramaAddr;
    HANDLE m_hProcess;
    DWORD m_dwProcessId;
    int size_Func;
    int size_Pramam;
    RemoteParam m_RParam;

public:
    BOOL enableDebugPriv(); //提升进程访问权限
    DWORD processNameToId(LPCTSTR lpszProcessName); //根据进程名称得到进程ID,如果有多个运行实例的话，返回第一个枚举到的进程的ID
    BOOL ClearHook(HANDLE hProcess); //清理钩子代码
    BOOL HookOn(HANDLE hProcess); //挂上API钩子
    BOOL HookOff(HANDLE hProcess); //摘掉API钩子
    BOOL InitHook(HANDLE hProcess); //初始化API钩子


    afx_msg void OnBnClickedButtonopen();
    afx_msg void OnBnClickedButtonclose();

    afx_msg void OnTimer(UINT_PTR nIDEvent);
protected:
    afx_msg LRESULT OnHookTextout(WPARAM wParam, LPARAM lParam);
    afx_msg LRESULT OnMyMousemove(WPARAM wParam, LPARAM lParam);


};
