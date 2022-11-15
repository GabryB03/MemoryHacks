using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace MemoryHacks
{
    public class WindowInfo
    {
        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern int GetWindowText(IntPtr hWnd, StringBuilder text, int count);

        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern int GetWindowTextLength(IntPtr hWnd);

        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr GetForegroundWindow();

        [DllImport("user32.dll")]
        private static extern bool SetWindowText(IntPtr hWnd, string text);

        [DllImport("user32.dll", CharSet = CharSet.Auto)]
        private static extern IntPtr SendMessage(IntPtr hWnd, UInt32 Msg, IntPtr wParam, IntPtr lParam);

        [DllImport("user32.dll")]
        private static extern bool IsWindowVisible(IntPtr hWnd);

        [DllImport("user32.dll")]
        private static extern bool SetForegroundWindow(IntPtr hWnd);

        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetWindowPlacement(IntPtr hWnd, ref WINDOWPLACEMENT lpwndpl);

        private struct WINDOWPLACEMENT
        {
            public int length;
            public int flags;
            public int showCmd;
            public System.Drawing.Point ptMinPosition;
            public System.Drawing.Point ptMaxPosition;
            public System.Drawing.Rectangle rcNormalPosition;
        }

        public IntPtr WindowHandle { get; private set; }
        public Process DiagnosticsProcess { get; private set; }
        public ProcessThread DiagnosticsThread { get; private set; }
        public uint ProcessId { get; private set; }
        public uint ThreadId { get; private set; }

        public string WindowText
        {
            get
            {
                try
                {
                    var intLength = GetWindowTextLength(WindowHandle) + 1;
                    var stringBuilder = new StringBuilder(intLength);

                    if (GetWindowText(WindowHandle, stringBuilder, intLength) > 0)
                    {
                        return stringBuilder.ToString();
                    }

                    return "";
                }
                catch
                {
                    return "";
                }
            }

            set
            {
                SetWindowText(WindowHandle, value);
            }
        }

        public string WindowTitle
        {
            get
            {
                try
                {
                    var intLength = GetWindowTextLength(WindowHandle) + 1;
                    var stringBuilder = new StringBuilder(intLength);

                    if (GetWindowText(WindowHandle, stringBuilder, intLength) > 0)
                    {
                        return stringBuilder.ToString();
                    }

                    return "";
                }
                catch
                {
                    return "";
                }
            }

            set
            {
                SetWindowText(WindowHandle, value);
            }
        }

        public bool IsFocused
        {
            get
            {
                try
                {
                    return GetForegroundWindow() == WindowHandle;
                }
                catch
                {
                    return false;
                }
            }

            set
            {
                if (value == true)
                {
                    SetFocusedWindow();
                }
            }
        }

        public bool IsMainWindow
        {
            get
            {
                try
                {
                    return WindowHandle == DiagnosticsProcess.MainWindowHandle;
                }
                catch
                {
                    return false;
                }
            }
        }

        public bool IsVisible
        {
            get
            {
                try
                {
                    return IsWindowVisible(WindowHandle);
                }
                catch
                {
                    return false;
                }
            }
        }

        public bool IsMinimized
        {
            get
            {
                try
                {
                    WINDOWPLACEMENT placement = new WINDOWPLACEMENT();
                    GetWindowPlacement(WindowHandle, ref placement);
                    return placement.showCmd == 2;
                }
                catch
                {
                    return false;
                }
            }

            set
            {
                if (value == true)
                {
                    MinimizeWindow();
                }
            }
        }

        public bool IsMaximized
        {
            get
            {
                try
                {
                    WINDOWPLACEMENT placement = new WINDOWPLACEMENT();
                    GetWindowPlacement(WindowHandle, ref placement);
                    return placement.showCmd == 3;
                }
                catch
                {
                    return false;
                }
            }

            set
            {
                if (value == true)
                {
                    MaximizeWindow();
                }
            }
        }

        public bool IsWindowShown
        {
            get
            {
                try
                {
                    WINDOWPLACEMENT placement = new WINDOWPLACEMENT();
                    GetWindowPlacement(WindowHandle, ref placement);
                    return placement.showCmd == 1;
                }
                catch
                {
                    return false;
                }
            }
        }

        public WindowInfo(IntPtr windowHandle, Process diagnosticsProcess, ProcessThread diagnosticsThread, uint processId, uint threadId)
        {
            WindowHandle = windowHandle;
            DiagnosticsProcess = diagnosticsProcess;
            DiagnosticsThread = diagnosticsThread;
            ProcessId = processId;
            ThreadId = threadId;
        }

        public void CloseWindow()
        {
            SendMessage(WindowHandle, 0x0010, IntPtr.Zero, IntPtr.Zero);
        }

        public void MinimizeWindow()
        {
            SendMessage(WindowHandle, 0x112, (IntPtr) 0xf020, IntPtr.Zero);
        }

        public void MaximizeWindow()
        {
            SendMessage(WindowHandle, 0x112, (IntPtr) 0xf030, IntPtr.Zero);
        }

        public void SetWindowTitle(string title)
        {
            WindowText = title;
        }

        public void SetWindowText(string title)
        {
            WindowText = title;
        }

        public void SetFocusedWindow()
        {
            SetForegroundWindow(WindowHandle);
        }

        public void FocusWindow()
        {
            SetFocusedWindow();
        }
    }
}