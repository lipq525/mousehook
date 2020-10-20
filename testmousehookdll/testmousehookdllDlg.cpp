
// testmousehookdllDlg.cpp: 实现文件
//

#include "pch.h"
#include "framework.h"
#include "testmousehookdll.h"
#include "testmousehookdllDlg.h"
#include "afxdialogex.h"
#include <TlHelp32.h>

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

#define TIME_ID_1 1

// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(IDD_ABOUTBOX)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CtestmousehookdllDlg 对话框



CtestmousehookdllDlg::CtestmousehookdllDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_TESTMOUSEHOOKDLL_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
    is_quci_open=FALSE;
    m_edit_str=_T("");
    m_hwnd_hook=NULL;
    bHookAlready=FALSE;
    dwFunAddr=NULL;
    dwPramaAddr=NULL;
    m_hProcess=NULL;
    m_dwProcessId=NULL;
    size_Func=0;
    size_Pramam=0;
    ::memset(oldcode,0,10);
    ::memset(newcode,0,10);

}

void CtestmousehookdllDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
    DDX_Control(pDX, IDC_EDIT_out_put, m_edit);
}

BEGIN_MESSAGE_MAP(CtestmousehookdllDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
    ON_BN_CLICKED(IDC_BUTTON_open, &CtestmousehookdllDlg::OnBnClickedButtonopen)
    ON_BN_CLICKED(IDC_BUTTON_close, &CtestmousehookdllDlg::OnBnClickedButtonclose)
    ON_MESSAGE(WM_HOOK_TEXTOUT, &CtestmousehookdllDlg::OnHookTextout)
    ON_WM_TIMER()
    ON_MESSAGE(WM_MY_MOUSEMOVE, &CtestmousehookdllDlg::OnMyMousemove)

END_MESSAGE_MAP()


// CtestmousehookdllDlg 消息处理程序

BOOL CtestmousehookdllDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != nullptr)
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

	// TODO: 在此添加额外的初始化代码

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CtestmousehookdllDlg::OnSysCommand(UINT nID, LPARAM lParam)
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

void CtestmousehookdllDlg::OnPaint()
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
HCURSOR CtestmousehookdllDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

//==========================================================================
//typedef HANDLE (__stdcall * PFN_CREATEFILE)(LPCWSTR,DWORD,DWORD,LPSECURITY_ATTRIBUTES,DWORD,DWORD,HANDLE);
typedef int (__stdcall * PFN_MESSAGEBOX)(HWND, LPCWSTR, LPCWSTR, DWORD);
typedef BOOL (__stdcall * PFN_WRITEPROCESSMEMORY)(HANDLE,LPVOID,LPCVOID,SIZE_T,SIZE_T*);
typedef HANDLE (__stdcall * PFN_GETCURRENTPROCESS)(void);
typedef BOOL (__stdcall * PFN_TEXTOUT)(HDC, int, int, LPCSTR, int);//TextOutA
typedef BOOL (__stdcall * PFN_TEXTOUTW)(HDC, int, int, LPCWSTR, int);//TextOutAW
typedef BOOL (__stdcall * PFN_EXTTEXTOUTA)(HDC, int, int, UINT, CONST RECT*, LPCSTR, UINT, CONST INT*);//ExtTextOutA
typedef BOOL (__stdcall * PFN_EXTTEXTOUTW)(HDC, int, int, UINT, CONST RECT*, LPCWSTR, UINT, CONST INT*);//ExtTextOutW
typedef BOOL (__stdcall * PFN_POSTMESSAGE)(HWND, UINT, WPARAM, LPARAM);
typedef BOOL (__stdcall * PFN_SENDMESSAGE)(HWND, UINT, WPARAM, LPARAM);
typedef int (__stdcall * PFN_MESSAGEBOX)(HWND, LPCWSTR, LPCWSTR, DWORD);

void HookTextOut(LPVOID lParam)
{
    RemoteParam* pRP=(RemoteParam*)lParam;

    DWORD dwParamaAddr=0; //自定义结构体的地址
    DWORD NextIpAddr=0; //CPU下一个IP地址

    HDC hdc=NULL; //设备描述表句柄，画图用的
    int x=0; //字符串的开始位置 x坐标
    int y=0; //字符串的开始位置 y坐标
    UINT options=0;
    CONST RECT *lprect=NULL;
    LPCWSTR lpString=NULL; //字符串指针
    int c=0; //字符串中字符的个数
    CONST INT * lpDx=NULL;
    BOOL Res=FALSE; //API TextOut 的返回值

                    //下面的汇编代码是将TextOut(...)里面的6个参数和另外两个变量(dwParamaAddr和NextIpAddr)保存到变量中,以便后面调用
    __asm 
    { 
        MOV EAX,[EBP+8] //注意是[EBP+8]，而不是[EBP+4]
        MOV [dwParamaAddr], EAX
        MOV EAX,[EBP+12]
        MOV [NextIpAddr], EAX
        MOV EAX,[EBP+16]
        MOV [hdc], EAX
        MOV EAX,[EBP+20]
        MOV [x], EAX
        MOV EAX,[EBP+24]
        MOV [y], EAX
        MOV EAX,[EBP+28]
        MOV [options], EAX
        MOV EAX,[EBP+32]
        MOV [lprect], EAX
        MOV EAX,[EBP+36]
        MOV [lpString], EAX
        MOV EAX,[EBP+40]
        MOV [c], EAX
        MOV EAX,[EBP+44]
        MOV [lpDx], EAX
    }

    PFN_GETCURRENTPROCESS pfnGetCurrentProcess=(PFN_GETCURRENTPROCESS)pRP->dwGetCurrentProcess;
    PFN_WRITEPROCESSMEMORY pfnWriteProcessMemory=(PFN_WRITEPROCESSMEMORY)pRP->dwWriteProcessMemory;
    PFN_TEXTOUT pfnTextOut=(PFN_TEXTOUT)pRP->dwTextOutA;
    PFN_TEXTOUTW pfnTextOutW=(PFN_TEXTOUTW)pRP->dwTextOutW;
    PFN_EXTTEXTOUTA pfnExtTextOutA=(PFN_EXTTEXTOUTA)pRP->dwExtTextOutA;
    PFN_EXTTEXTOUTW pfnExtTextOutW=(PFN_EXTTEXTOUTW)pRP->dwExtTextOutW;
    PFN_POSTMESSAGE pfnPostMessage=(PFN_POSTMESSAGE)pRP->dwPostMessage;
    PFN_SENDMESSAGE pfnSendMessage=(PFN_SENDMESSAGE)pRP->dwSendMessage;
    PFN_MESSAGEBOX pfnMessageBox=(PFN_MESSAGEBOX)pRP->dwMessageBox;

    //恢复API原来的样子，即摘掉API钩子
    pfnWriteProcessMemory(pfnGetCurrentProcess(), (LPVOID)pfnExtTextOutW, (LPCVOID)pRP->oldCode, 10, NULL);

    //调用正常的TextOut
    //	Res=pfnTextOut(hdc, x, y, lpString, c);
    Res=pfnExtTextOutW(hdc, x, y, options, lprect, lpString, c, lpDx);

    //下面的代码是将TextOut里面的lpString悄悄发送给我们挂钩子的windows应用程序
    if(pRP->hwnd!=NULL)
    {
        pRP->lpString=lpString;
        //		pfnPostMessage(pRP->hwnd, WM_HOOK_TEXTOUT, MAKELONG(0,0), MAKELONG(0,0)); //进程间通信
        pfnSendMessage(pRP->hwnd, WM_HOOK_TEXTOUT, MAKELONG(0,0), MAKELONG(0,0)); //进程间通信
    }

    //	int allowFlag = pfnMessageBox(NULL, lpString, pRP->info, MB_ICONWARNING | MB_YESNO);

    //下面代码是善后工作，这个非常重要，如果没有的话，EIP将回不到调用TextOut(...)的下一条命令，这条命令在"notepad.exe"的领空
    //而不是kernel32.dll的领空，要切记。
    __asm 
    {
        POP EDI
        POP ESI
        POP EBX
        MOV EDX, [NextIpAddr] //调用TextOut(...)这一命令的下一条命令地址
        MOV EAX, [Res] //函数返回值要放到EAX寄存器里，这一句可省略，原因是pfnTextOut(...)会自动将结果存入EAX
        MOV ESP, EBP
        POP EBP
        //		MOV ESP, EBP
        ADD ESP, 11*4 //此处为了平衡栈，可以进一步优化
        PUSH EDX
        RET //ret指令用栈中的数据(即edx里面的地址)，修改IP的内容，注意不修改CS的内容，retf才是 
    }
}


BOOL CtestmousehookdllDlg::enableDebugPriv()
{
    HANDLE hToken;  
    LUID sedebugnameValue;  
    TOKEN_PRIVILEGES tkp;  

    if(!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))  
    {  
        return FALSE;  
    }  
    if(!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &sedebugnameValue))  
    {  
        CloseHandle(hToken);  
        return FALSE;  
    }  
    tkp.PrivilegeCount = 1;  
    tkp.Privileges[0].Luid = sedebugnameValue;  
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED; //特权启用  
    if(!AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(tkp), NULL, NULL)) //启用指定访问令牌的特权  
    {  
        CloseHandle(hToken);  
        return FALSE;  
    }  
    return TRUE;
}

DWORD CtestmousehookdllDlg::processNameToId(LPCTSTR lpszProcessName)
{
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);
    if(!Process32First(hSnapshot, &pe))
    {
        MessageBox(_T("The frist entry of the process list has not been copyied to the buffer"), _T("Notice"), MB_ICONINFORMATION | MB_OK);  
        return 0;
    }
    while(Process32Next(hSnapshot, &pe)) //循环查找下一个进程
    {
        if(!strcmp(lpszProcessName, pe.szExeFile)) //找到了
        {
            return pe.th32ProcessID;
        }
    }

    return 0;
}

BOOL CtestmousehookdllDlg::InitHook(HANDLE hProcess)
{
    //提升进程访问权限
    if(!enableDebugPriv()) 
    { 
        printf("提升进程访问权限 Error!\n"); 
        MessageBox("提升进程访问权限 Error");
        return -1; 
    }

    //定义线程体的大小，实际分配的内存大小是页内存大小的整数倍
    size_Func=1024*8;

    dwFunAddr = (DWORD)VirtualAllocEx(hProcess, NULL, size_Func, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE); 
    if((LPVOID)dwFunAddr == NULL) 
    {
        printf("申请线程内存失败!\n"); 
        CloseHandle(hProcess); 
        return FALSE; 
    }

    size_Pramam=sizeof(RemoteParam);
    dwPramaAddr = (DWORD)VirtualAllocEx(hProcess, NULL, size_Pramam, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if((LPVOID)dwPramaAddr == NULL) 
    { 
        printf("申请参数内存失败!\n"); 
        CloseHandle(hProcess); 
        return FALSE; 
    }

    //	RemoteParam m_RParam;
    ZeroMemory(&m_RParam, sizeof(m_RParam));
    HMODULE hKernel32 = LoadLibrary("kernel32.dll");
    HMODULE hUser32 = LoadLibrary("user32.dll");
    HMODULE hGdi32 = LoadLibrary("gdi32.dll");

    m_RParam.dwTextOutA = (DWORD)GetProcAddress(hGdi32, "TextOutA");
    m_RParam.dwTextOutW = (DWORD)GetProcAddress(hGdi32, "TextOutW");
    m_RParam.dwExtTextOutW = (DWORD)GetProcAddress(hGdi32, "ExtTextOutW");
    m_RParam.dwExtTextOutA = (DWORD)GetProcAddress(hGdi32, "ExtTextOutA");
    m_RParam.dwGetCurrentProcess = (DWORD)GetProcAddress(hKernel32, "GetCurrentProcess");
    m_RParam.dwWriteProcessMemory = (DWORD)GetProcAddress(hKernel32, "WriteProcessMemory");
    m_RParam.dwPostMessage = (DWORD)GetProcAddress(hUser32, "PostMessageW");
    m_RParam.dwSendMessage = (DWORD)GetProcAddress(hUser32, "SendMessageW");
    m_RParam.dwMessageBox = (DWORD)GetProcAddress(hUser32, "MessageBoxW");

    m_RParam.bHookAlready=TRUE;
    m_RParam.hwnd=m_hwnd_hook;
    m_RParam.lpString=NULL;

    wchar_t str2[]={L"我拦截API成功了，哈哈^o^"};  
    ::wmemcpy_s(m_RParam.info,sizeof(m_RParam.info),str2,sizeof(str2));  
    for(int i=15; i<31; i++){m_RParam.info[i]=L'\0';}

    //	unsigned char oldcode[10]; 
    //	unsigned char newcode[10]; 
    int praadd = (int)dwPramaAddr; 
    int threadadd = (int)dwFunAddr; 
    newcode[4] = praadd>>24; 
    newcode[3] = (praadd<<8)>>24; 
    newcode[2] = (praadd<<16)>>24; 
    newcode[1] = (praadd<<24)>>24; 
    newcode[0] = 0x68; //0x68: push newcode[1..4]，参数先压栈

    int offsetaddr = threadadd - (int)m_RParam.dwExtTextOutA - 10 ; 
    newcode[9] = offsetaddr>>24; 
    newcode[8] = (offsetaddr<<8)>>24; 
    newcode[7] = (offsetaddr<<16)>>24; 
    newcode[6] = (offsetaddr<<24)>>24; 
    newcode[5] = 0xE8; //0xE8: call newcode[6..9]，然后调用函数

    for(int i = 0; i < 10; i++){m_RParam.newCode[i]=newcode[i];}

    CString str_oldcode;
    str_oldcode="m_RParam.NewCode: ";
    for(int i = 0; i< 10; i++){CString str;str.Format("0x%.2x ", m_RParam.newCode[i]);str_oldcode+=str;}
    str_oldcode+="\r\n";

    DWORD dwRead = 0;

    if(!ReadProcessMemory(GetCurrentProcess(), (LPCVOID)m_RParam.dwExtTextOutW, oldcode, 10, &dwRead)) 
    {
        printf("read error");
        CloseHandle(hProcess);
        FreeLibrary(hKernel32);
        FreeLibrary(hUser32);
        FreeLibrary(hGdi32);
        return FALSE;
    }

    strcat((char*)m_RParam.oldCode, (char*)oldcode);
    m_RParam.FunAddr = dwFunAddr;

    str_oldcode+="m_RParam.OldCode: ";
    for(int i = 0; i< 10; i++){CString str;str.Format("0x%.2x ", m_RParam.oldCode[i]);str_oldcode+=str;}
    str_oldcode+="\n";

    DWORD dwWrite = 0;

    if(!WriteProcessMemory(hProcess, (LPVOID)dwFunAddr, (LPVOID)&HookTextOut, size_Func, &dwWrite))
    {
        printf("WriteRemoteProcessesMemory Error 1 !\n");
        CloseHandle(hProcess);
        FreeLibrary(hKernel32);
        FreeLibrary(hUser32);
        FreeLibrary(hGdi32);
        return FALSE;
    }

    if(!WriteProcessMemory(hProcess, (LPVOID)dwPramaAddr, (LPVOID)&m_RParam, sizeof(RemoteParam), &dwWrite))
    {
        printf("WriteRemoteProcessesMemory Error 2 !\n");
        CloseHandle(hProcess);
        FreeLibrary(hKernel32);
        FreeLibrary(hUser32);
        FreeLibrary(hGdi32);
        return FALSE;
    }

    FreeLibrary(hKernel32);
    FreeLibrary(hUser32);
    FreeLibrary(hGdi32);

    CString str;
    str.Format("m_RParam.dwExtTextOut:%.8x\r\nRParam.dwMessageBox:%.8x\r\nRParam.dwGetCurrentProcess:%.8x\r\nRParam.dwWriteProcessMemory:%.8x\r\nRParam.FunAddr:%.8x\r\ndwPramaAddr=%.8x\r\n",   
        m_RParam.dwExtTextOutW, m_RParam.dwMessageBox, m_RParam.dwGetCurrentProcess, m_RParam.dwWriteProcessMemory, m_RParam.FunAddr, dwPramaAddr);

    str+=str_oldcode;
    m_edit.SetWindowText(str);

    return TRUE;
}

BOOL CtestmousehookdllDlg::ClearHook(HANDLE hProcess)
{
    HookOff(m_hProcess);
    VirtualFreeEx(m_hProcess, (LPVOID)dwFunAddr, 0, MEM_RELEASE); //MEM_DECOMMIT仅标示内存空间不可用，内存页还将存在。MEM_RELEASE完全回收。
    VirtualFreeEx(m_hProcess, (LPVOID)dwPramaAddr, 0, MEM_RELEASE); //MEM_DECOMMIT仅标示内存空间不可用，内存页还将存在。MEM_RELEASE完全回收。
    dwFunAddr=NULL;
    dwPramaAddr=NULL;
    m_hProcess=NULL;
    return TRUE;
}


BOOL CtestmousehookdllDlg::HookOn(HANDLE hProcess)
{
    DWORD dwWrite=0;
    if(!WriteProcessMemory(hProcess, (LPVOID)m_RParam.dwExtTextOutW, (LPVOID)newcode, 10, &dwWrite)) //挂上API钩子
    {
        printf("WriteRemoteProcessesMemory Error 4 !\n");
        return FALSE;
    }

    return TRUE;
}

BOOL CtestmousehookdllDlg::HookOff(HANDLE hProcess)
{
    DWORD dwWrite=0;
    if(!WriteProcessMemory(hProcess, (LPVOID)m_RParam.dwExtTextOutW, (LPVOID)oldcode, 10, &dwWrite)) //摘掉API钩子
    {
        printf("WriteRemoteProcessesMemory Error 5 !\n");
        return FALSE;
    }

    return TRUE;
}



void CtestmousehookdllDlg::OnBnClickedButtonopen()
{
    // TODO: 在此添加控件通知处理程序代码
    m_hwnd_hook=this->GetSafeHwnd(); //将对话框设置为安装API钩子的元凶
    m_mouse_hook.StartHook(m_hwnd_hook); //开启全局鼠标钩子

}


void CtestmousehookdllDlg::OnBnClickedButtonclose()
{
    // TODO: 在此添加控件通知处理程序代码
    m_mouse_hook.StopHook(m_hwnd_hook); //关闭全局鼠标钩子

}


afx_msg LRESULT CtestmousehookdllDlg::OnHookTextout(WPARAM wParam, LPARAM lParam)
{
    wchar_t str[200];
    ZeroMemory(str, sizeof(str)/sizeof(wchar_t));

    RemoteParam RParam;
    ZeroMemory(&RParam, sizeof(RParam));

    DWORD dwRead=0;
    if(!ReadProcessMemory(m_hProcess, (LPCVOID)dwPramaAddr, &RParam, sizeof(RParam), &dwRead))
    {
        printf("read error");
        CloseHandle(m_hProcess);
        return 1;
    }
    if(!ReadProcessMemory(m_hProcess, (LPCVOID)RParam.lpString, str, sizeof(str), &dwRead))
    {
        printf("read error");
        CloseHandle(m_hProcess);
        return 1;
    }

    char sss[400];
    ZeroMemory(sss, sizeof(sss)/sizeof(char));

    int len=WideCharToMultiByte(CP_ACP,0,str,-1,NULL,0,NULL,NULL);
    WideCharToMultiByte(CP_ACP,0,str,-1,sss,len,NULL,NULL); //宽字符转多字节字符

    m_edit.SetWindowText(sss); //将截取来的字符串显示到对话框的文本框里面

    return 0;
}


void CtestmousehookdllDlg::OnTimer(UINT_PTR nIDEvent)
{
    // TODO: 在此添加消息处理程序代码和/或调用默认值

    if(nIDEvent==TIME_ID_1)
    {
        this->KillTimer(TIME_ID_1);
        POINT pt;
        GetCursorPos(&pt);

        CWnd* pWnd=WindowFromPoint(pt);
        if(pWnd!=NULL)
        {
            HWND hwnd=pWnd->GetSafeHwnd();

            DWORD dwProcessId=NULL;
            GetWindowThreadProcessId(hwnd, &dwProcessId); //获取进程ID
            if(dwProcessId!=NULL)
            {
                if(m_dwProcessId!=dwProcessId)
                {
                    if(m_hProcess!=NULL){ClearHook(m_hProcess);}
                    m_hProcess=OpenProcess(PROCESS_VM_OPERATION|PROCESS_VM_WRITE|PROCESS_VM_READ, FALSE, dwProcessId);
                    m_dwProcessId=dwProcessId;
                    InitHook(m_hProcess);
                }

                HookOn(m_hProcess); //挂上API钩子
                RECT rc;
                rc.left=pt.x-2;
                rc.right=pt.x+2;
                rc.top=pt.y;
                rc.bottom=pt.y+4;
                pWnd->ScreenToClient(&rc);
                pWnd->InvalidateRect(&rc); //使矩形区域失效，放入WM_PAINT消息
                pWnd->UpdateWindow(); //强制更新
                HookOff(m_hProcess); //摘掉API钩子
            }
        }
    }

    CDialogEx::OnTimer(nIDEvent);
}


afx_msg LRESULT CtestmousehookdllDlg::OnMyMousemove(WPARAM wParam, LPARAM lParam)
{
    this->KillTimer(TIME_ID_1);
    this->SetTimer(TIME_ID_1,1000,NULL); //设置鼠标在屏幕某处停留1秒的时钟

    return 0;
}
