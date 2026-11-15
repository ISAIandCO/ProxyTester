"""Optional Windows QA capture using native GDI, no runtime dependency."""
import ctypes
import struct
from ctypes import wintypes as w
from pathlib import Path


def capture(root, path):
    user, gdi = ctypes.windll.user32, ctypes.windll.gdi32
    user.GetWindowDC.argtypes, user.GetWindowDC.restype = [w.HWND], w.HDC
    user.ReleaseDC.argtypes = [w.HWND, w.HDC]
    gdi.CreateCompatibleDC.argtypes, gdi.CreateCompatibleDC.restype = [w.HDC], w.HDC
    gdi.CreateCompatibleBitmap.argtypes, gdi.CreateCompatibleBitmap.restype = [w.HDC, ctypes.c_int, ctypes.c_int], w.HBITMAP
    gdi.SelectObject.argtypes, gdi.SelectObject.restype = [w.HDC, w.HANDLE], w.HANDLE
    gdi.DeleteObject.argtypes = [w.HANDLE]
    gdi.DeleteDC.argtypes = [w.HDC]
    user.GetWindowRect.argtypes = [w.HWND, ctypes.POINTER(w.RECT)]
    user.PrintWindow.argtypes = [w.HWND, w.HDC, w.UINT]
    gdi.GetDIBits.argtypes = [w.HDC, w.HBITMAP, w.UINT, w.UINT, ctypes.c_void_p, ctypes.c_void_p, w.UINT]
    hwnd = int(root.frame(), 0)
    rect = w.RECT()
    user.GetWindowRect(hwnd, ctypes.byref(rect))
    width, height = rect.right - rect.left, rect.bottom - rect.top
    dc = user.GetWindowDC(hwnd)
    memory = gdi.CreateCompatibleDC(dc)
    bitmap = gdi.CreateCompatibleBitmap(dc, width, height)
    previous = gdi.SelectObject(memory, bitmap)
    try:
        if not user.PrintWindow(hwnd, memory, 0):
            raise OSError("PrintWindow failed")
        gdi.SelectObject(memory, previous)
        size = ((width * 24 + 31) // 32) * 4 * height
        info = ctypes.create_string_buffer(struct.pack("<IiiHHIIiiII", 40, width, height, 1, 24, 0, size, 0, 0, 0, 0))
        pixels = ctypes.create_string_buffer(size)
        if not gdi.GetDIBits(dc, bitmap, 0, height, pixels, info, 0):
            raise OSError("GetDIBits failed")
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(struct.pack("<2sIHHI", b"BM", 54 + size, 0, 0, 54) + info.raw[:40] + pixels.raw)
    finally:
        gdi.DeleteObject(bitmap)
        gdi.DeleteDC(memory)
        user.ReleaseDC(hwnd, dc)
