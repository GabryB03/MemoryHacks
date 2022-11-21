using System;
using System.Diagnostics;
using System.Drawing;
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

        [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern int GetClassName(IntPtr hWnd, StringBuilder lpClassName, int nMaxCount);

        private struct WINDOWPLACEMENT
        {
            public int length;
            public int flags;
            public int showCmd;
            public Point ptMinPosition;
            public Point ptMaxPosition;
            public Rectangle rcNormalPosition;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct RECT
        {
            public int Left;
            public int Top;
            public int Right;
            public int Bottom;
        }

        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool GetWindowRect(IntPtr hwnd, out RECT lpRect);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool MoveWindow(IntPtr hWnd, int X, int Y, int nWidth, int nHeight, bool bRepaint);

        public int X
        {
            get
            {
                RECT rect;
                GetWindowRect(WindowHandle, out rect);
                return rect.Left;
            }

            set
            {
                RECT rect;
                GetWindowRect(WindowHandle, out rect);
                int Y = rect.Top;
                int Width = rect.Right - rect.Left;
                int Height = rect.Bottom - rect.Top;
                MoveWindow(WindowHandle, value, Y, Width, Height, true);
            }
        }

        public int Y
        {
            get
            {
                RECT rect;
                GetWindowRect(WindowHandle, out rect);
                return rect.Top;
            }

            set
            {
                RECT rect;
                GetWindowRect(WindowHandle, out rect);
                int X = rect.Left;
                int Width = rect.Right - rect.Left;
                int Height = rect.Bottom - rect.Top;
                MoveWindow(WindowHandle, X, value, Width, Height, true);
            }
        }

        public int Width
        {
            get
            {
                RECT rect;
                GetWindowRect(WindowHandle, out rect);
                return rect.Right - rect.Left;
            }

            set
            {
                RECT rect;
                GetWindowRect(WindowHandle, out rect);
                int X = rect.Left;
                int Y = rect.Top;
                int Height = rect.Bottom - rect.Top;
                MoveWindow(WindowHandle, X, Y, value, Height, true);
            }
        }

        public int Height
        {
            get
            {
                RECT rect;
                GetWindowRect(WindowHandle, out rect);
                return rect.Bottom - rect.Top;
            }

            set
            {
                RECT rect;
                GetWindowRect(WindowHandle, out rect);
                int X = rect.Left;
                int Y = rect.Top;
                int Width = rect.Right - rect.Left;
                MoveWindow(WindowHandle, X, Y, Width, value, true);
            }
        }

        public Point Location
        {
            get
            {
                return new Point(X, Y);
            }

            set
            {
                Point thePoint = value;
                X = thePoint.X;
                Y = thePoint.Y;
            }
        }

        public Size Size
        {
            get
            {
                return new Size(Width, Height);
            }

            set
            {
                Size theSize = value;
                Width = theSize.Width;
                Height = theSize.Height;
            }
        }

        public Rectangle Rectangle
        {
            get
            {
                return new Rectangle(X, Y, Width, Height);
            }

            set
            {
                Rectangle theRectangle = value;
                X = theRectangle.X;
                Y = theRectangle.Y;
                Width = theRectangle.Width;
                Height = theRectangle.Height;
            }
        }

        public string ClassName
        {
            get
            {
                int nRet = 0;
                StringBuilder ClassName = new StringBuilder(256);
                nRet = GetClassName(WindowHandle, ClassName, ClassName.Capacity);
                
                if (nRet == 0)
                {
                    return null;
                }

                return ClassName.ToString();
            }
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

        public void Activate()
        {
            SetFocusedWindow();
        }
    }
}