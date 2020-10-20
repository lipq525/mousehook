#pragma once

#define WM_MY_MOUSEMOVE (WM_USER+10)

// CMyMoueHook 命令目标

class AFX_EXT_CLASS CMyMouseHook:public CObject
{
public:
    CMyMouseHook();
    virtual ~CMyMouseHook();

public:
    BOOL StartHook(HWND hWnd); //安装钩子函数
    BOOL StopHook(HWND hWnd); //卸载钩子函数
};

