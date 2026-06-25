from __future__ import annotations

import ctypes
import os
import threading
from ctypes import wintypes
from pathlib import Path

from sunpack.config.payload_io import read_config_payload
from sunpack.passwords.internal.clipboard import read_clipboard_passwords
from sunpack.platform.windows.startup import disable_startup, enable_startup, startup_status


WM_DESTROY = 0x0002
WM_COMMAND = 0x0111
WM_USER = 0x0400
WM_TRAYICON = WM_USER + 20
WM_CLOSE = 0x0010
NIM_ADD = 0x00000000
NIM_DELETE = 0x00000002
NIF_MESSAGE = 0x00000001
NIF_ICON = 0x00000002
NIF_TIP = 0x00000004
LR_LOADFROMFILE = 0x00000010
IMAGE_ICON = 1
MF_STRING = 0x00000000
TPM_RIGHTBUTTON = 0x0002
WM_RBUTTONUP = 0x0205
WM_LBUTTONDBLCLK = 0x0203
IDI_APPLICATION = 32512
SW_SHOWNORMAL = 1
LRESULT = getattr(wintypes, "LRESULT", ctypes.c_ssize_t)
WPARAM = getattr(wintypes, "WPARAM", ctypes.c_size_t)
LPARAM = getattr(wintypes, "LPARAM", ctypes.c_void_p)

ID_OPEN_CONFIG = 1001
ID_OPEN_LOG_DIR = 1002
ID_ADD_CLIPBOARD = 1003
ID_RELOAD = 1004
ID_EXIT = 1005
ID_TOGGLE_STARTUP = 1006


class WindowsTrayIcon:
    def __init__(self, service):
        self.service = service
        self.user32 = ctypes.windll.user32
        self.shell32 = ctypes.windll.shell32
        self.kernel32 = ctypes.windll.kernel32
        self.kernel32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
        self.kernel32.GetModuleHandleW.restype = wintypes.HINSTANCE
        self.user32.RegisterClassW.argtypes = [ctypes.POINTER(WNDCLASS)]
        self.user32.RegisterClassW.restype = wintypes.ATOM
        self.user32.CreateWindowExW.argtypes = [
            wintypes.DWORD,
            wintypes.LPCWSTR,
            wintypes.LPCWSTR,
            wintypes.DWORD,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_int,
            wintypes.HWND,
            wintypes.HMENU,
            wintypes.HINSTANCE,
            wintypes.LPVOID,
        ]
        self.user32.CreateWindowExW.restype = wintypes.HWND
        self.user32.DefWindowProcW.argtypes = [wintypes.HWND, wintypes.UINT, WPARAM, LPARAM]
        self.user32.DefWindowProcW.restype = LRESULT
        self._thread: threading.Thread | None = None
        self._ready = threading.Event()
        self._hwnd = None
        self._icon = None
        self._wndproc_ref = None

    def start(self) -> None:
        if os.name != "nt" or self._thread is not None:
            return
        self._thread = threading.Thread(target=self._run, name="sunpack-tray", daemon=True)
        self._thread.start()
        self._ready.wait(timeout=2.0)

    def stop(self) -> None:
        hwnd = self._hwnd
        if hwnd:
            try:
                self.user32.PostMessageW(hwnd, WM_CLOSE, 0, 0)
            except Exception:
                pass
        thread = self._thread
        if thread is not None:
            thread.join(timeout=2.0)
        self._thread = None

    def _run(self) -> None:
        hwnd = self._create_window()
        if not hwnd:
            self._ready.set()
            return
        self._hwnd = hwnd
        self._add_icon(hwnd)
        self._ready.set()
        msg = wintypes.MSG()
        while self.user32.GetMessageW(ctypes.byref(msg), None, 0, 0) > 0:
            self.user32.TranslateMessage(ctypes.byref(msg))
            self.user32.DispatchMessageW(ctypes.byref(msg))
        self._delete_icon(hwnd)

    def _create_window(self):
        wndproc_type = ctypes.WINFUNCTYPE(LRESULT, wintypes.HWND, wintypes.UINT, WPARAM, LPARAM)
        self._wndproc_ref = wndproc_type(self._wndproc)
        hinstance = self.kernel32.GetModuleHandleW(None)
        wndclass = WNDCLASS()
        wndclass.lpfnWndProc = ctypes.cast(self._wndproc_ref, ctypes.c_void_p)
        wndclass.hInstance = hinstance
        wndclass.lpszClassName = "SunpackWatchServiceTray"
        self.user32.RegisterClassW(ctypes.byref(wndclass))
        return self.user32.CreateWindowExW(
            0,
            wndclass.lpszClassName,
            wndclass.lpszClassName,
            0,
            0,
            0,
            0,
            0,
            None,
            None,
            hinstance,
            None,
        )

    def _add_icon(self, hwnd) -> None:
        data = NOTIFYICONDATA()
        data.cbSize = ctypes.sizeof(NOTIFYICONDATA)
        data.hWnd = hwnd
        data.uID = 1
        data.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP
        data.uCallbackMessage = WM_TRAYICON
        data.hIcon = self._load_icon()
        data.szTip = "SunPack Watch"
        self.shell32.Shell_NotifyIconW(NIM_ADD, ctypes.byref(data))

    def _delete_icon(self, hwnd) -> None:
        data = NOTIFYICONDATA()
        data.cbSize = ctypes.sizeof(NOTIFYICONDATA)
        data.hWnd = hwnd
        data.uID = 1
        self.shell32.Shell_NotifyIconW(NIM_DELETE, ctypes.byref(data))

    def _load_icon(self):
        repo_icon = Path(__file__).resolve().parents[3] / "sunpack.ico"
        if repo_icon.exists():
            icon = self.user32.LoadImageW(None, str(repo_icon), IMAGE_ICON, 0, 0, LR_LOADFROMFILE)
            if icon:
                self._icon = icon
                return icon
        return self.user32.LoadIconW(None, ctypes.c_wchar_p(IDI_APPLICATION))

    def _wndproc(self, hwnd, msg, wparam, lparam):
        if msg == WM_TRAYICON and lparam in {WM_RBUTTONUP, WM_LBUTTONDBLCLK}:
            self._show_menu(hwnd)
            return 0
        if msg == WM_COMMAND:
            self._handle_command(int(wparam) & 0xFFFF)
            return 0
        if msg in {WM_CLOSE, WM_DESTROY}:
            self._delete_icon(hwnd)
            self.user32.DestroyWindow(hwnd)
            self.user32.PostQuitMessage(0)
            return 0
        return self.user32.DefWindowProcW(hwnd, msg, wparam, lparam)

    def _show_menu(self, hwnd) -> None:
        menu = self.user32.CreatePopupMenu()
        self.user32.AppendMenuW(menu, MF_STRING, ID_OPEN_CONFIG, "Open config")
        self.user32.AppendMenuW(menu, MF_STRING, ID_OPEN_LOG_DIR, "Open log directory")
        self.user32.AppendMenuW(menu, MF_STRING, ID_ADD_CLIPBOARD, "Add clipboard path")
        self.user32.AppendMenuW(menu, MF_STRING, ID_TOGGLE_STARTUP, self._startup_menu_label())
        self.user32.AppendMenuW(menu, MF_STRING, ID_RELOAD, "Reload")
        self.user32.AppendMenuW(menu, MF_STRING, ID_EXIT, "Exit")
        point = wintypes.POINT()
        self.user32.GetCursorPos(ctypes.byref(point))
        self.user32.SetForegroundWindow(hwnd)
        self.user32.TrackPopupMenu(menu, TPM_RIGHTBUTTON, point.x, point.y, 0, hwnd, None)
        self.user32.DestroyMenu(menu)

    def _handle_command(self, command_id: int) -> None:
        if command_id == ID_OPEN_CONFIG:
            config_path, _ = read_config_payload()
            self._open_path(str(config_path))
        elif command_id == ID_OPEN_LOG_DIR:
            self._open_path(self.service.state_dir)
        elif command_id == ID_ADD_CLIPBOARD:
            self.service.add_clipboard_path(read_clipboard_passwords)
        elif command_id == ID_TOGGLE_STARTUP:
            self._toggle_startup()
        elif command_id == ID_RELOAD:
            self.service.request_reload()
        elif command_id == ID_EXIT:
            self.service.request_stop()
            if self._hwnd:
                self.user32.PostMessageW(self._hwnd, WM_CLOSE, 0, 0)

    def _open_path(self, path: str) -> None:
        self.shell32.ShellExecuteW(None, "open", path, None, None, SW_SHOWNORMAL)

    def _startup_menu_label(self) -> str:
        try:
            enabled, _ = startup_status()
        except Exception:
            enabled = False
        return "Disable startup" if enabled else "Enable startup"

    def _toggle_startup(self) -> None:
        try:
            enabled, _ = startup_status()
            if enabled:
                disable_startup()
            else:
                enable_startup()
        except Exception:
            return


class WNDCLASS(ctypes.Structure):
    _fields_ = [
        ("style", wintypes.UINT),
        ("lpfnWndProc", ctypes.c_void_p),
        ("cbClsExtra", ctypes.c_int),
        ("cbWndExtra", ctypes.c_int),
        ("hInstance", wintypes.HINSTANCE),
        ("hIcon", wintypes.HANDLE),
        ("hCursor", wintypes.HANDLE),
        ("hbrBackground", wintypes.HANDLE),
        ("lpszMenuName", wintypes.LPCWSTR),
        ("lpszClassName", wintypes.LPCWSTR),
    ]


class NOTIFYICONDATA(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.DWORD),
        ("hWnd", wintypes.HWND),
        ("uID", wintypes.UINT),
        ("uFlags", wintypes.UINT),
        ("uCallbackMessage", wintypes.UINT),
        ("hIcon", wintypes.HANDLE),
        ("szTip", wintypes.WCHAR * 128),
        ("dwState", wintypes.DWORD),
        ("dwStateMask", wintypes.DWORD),
        ("szInfo", wintypes.WCHAR * 256),
        ("uVersion", wintypes.UINT),
        ("szInfoTitle", wintypes.WCHAR * 64),
        ("dwInfoFlags", wintypes.DWORD),
        ("guidItem", ctypes.c_byte * 16),
        ("hBalloonIcon", wintypes.HANDLE),
    ]
