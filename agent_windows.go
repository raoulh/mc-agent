// +build windows

package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"os"
	"reflect"
	"syscall"
	"unsafe"

	"github.com/lxn/win"
)

var (
	modkernel32         = syscall.NewLazyDLL("kernel32.dll")
	procOpenFileMapping = modkernel32.NewProc("OpenFileMappingW")

	sshAgent *SshAgent
)

const (
	PAGEANT_NAME      = "Pageant"
	AGENT_COPYDATA_ID = 0x804e50ba
	AGENT_MAX_MSGLEN  = 8192
)

type PageantWin struct {
	hwnd   win.HWND
	hInst  win.HINSTANCE
	wClass win.WNDCLASSEX
}

type COPYDATASTRUCT struct {
	dwData uintptr
	cbData uint32
	lpData uintptr
}

type memoryMap []byte

func (m *memoryMap) header() *reflect.SliceHeader {
	return (*reflect.SliceHeader)(unsafe.Pointer(m))
}

func OpenFileMapping(dwDesiredAccess uint32, bInheritHandle uint32, lpName string) syscall.Handle {
	param1 := uintptr(dwDesiredAccess)
	param2 := uintptr(bInheritHandle)
	param3 := uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(lpName)))
	ret, _, _ := procOpenFileMapping.Call(param1, param2, param3)

	return syscall.Handle(ret)
}

func RunAgent() {
	log.Println("Starting Moolticute Pageant")

	if isPageantRunning() {
		log.Println("A Pageant is already running. Abort.")
		return
	}

	p, err := createPageantWindow()
	if err != nil {
		log.Println("Can't create pageant window:", err)
		return
	}

	sshAgent = NewSshAgent()

	p.WaitMessage()
}

func isPageantRunning() (r bool) {
	if win.FindWindow(syscall.StringToUTF16Ptr(PAGEANT_NAME), syscall.StringToUTF16Ptr(PAGEANT_NAME)) != 0 {
		r = true
	}
	return
}

func createPageantWindow() (p *PageantWin, err error) {
	p = &PageantWin{
		hInst: win.GetModuleHandle(nil),
	}

	p.wClass.CbSize = uint32(unsafe.Sizeof(p.wClass))
	p.wClass.LpfnWndProc = syscall.NewCallback(p.PageantWndProc)
	p.wClass.HInstance = p.hInst
	p.wClass.HIcon = win.LoadIcon(0, (*uint16)(unsafe.Pointer(uintptr(win.IDI_APPLICATION))))
	p.wClass.HCursor = win.LoadCursor(0, (*uint16)(unsafe.Pointer(uintptr(win.IDC_ARROW))))
	p.wClass.HbrBackground = win.COLOR_WINDOW + 1
	p.wClass.LpszClassName = syscall.StringToUTF16Ptr(PAGEANT_NAME)
	p.wClass.HIconSm = win.LoadIcon(0, (*uint16)(unsafe.Pointer(uintptr(win.IDI_APPLICATION))))

	if atom := win.RegisterClassEx(&p.wClass); atom == 0 {
		return nil, fmt.Errorf("Failed to RegisterClassEx: %v", syscall.GetLastError())
	}

	p.hwnd = win.CreateWindowEx(
		0,
		syscall.StringToUTF16Ptr(PAGEANT_NAME),
		syscall.StringToUTF16Ptr(PAGEANT_NAME),
		win.WS_OVERLAPPEDWINDOW|win.WS_VSCROLL,
		win.CW_USEDEFAULT,
		win.CW_USEDEFAULT,
		win.CW_USEDEFAULT,
		win.CW_USEDEFAULT,
		0,
		0,
		p.hInst,
		nil)

	if p.hwnd == 0 {
		return nil, fmt.Errorf("Failed to CreateWindowEx: %v", syscall.GetLastError())
	}

	win.ShowWindow(p.hwnd, win.SW_HIDE)

	return
}

func getLastError() string {
	err := syscall.GetLastError()
	return err.Error()
}

func (p *PageantWin) PageantWndProc(hwnd win.HWND, msg uint, wparam, lparam uintptr) uintptr {
	if msg == win.WM_COPYDATA {
		ldata := (*COPYDATASTRUCT)(unsafe.Pointer(lparam))
		handleWmCopyMessage(ldata)
		return 1
	}
	return win.DefWindowProc(hwnd, uint32(msg), wparam, lparam)
}

func (p *PageantWin) WaitMessage() {
	var msg win.MSG
	for win.GetMessage(&msg, 0, 0, 0) != -1 {
		win.TranslateMessage(&msg)
		win.DispatchMessage(&msg)

		if msg.Message == win.WM_QUIT {
			log.Println("exit app")
			break
		}
	}
}

type readWriter struct {
	io.Reader
	io.Writer
}

func NewReadWriter(r io.Reader, w io.Writer) io.ReadWriter {
	return &readWriter{r, w}
}

func getMemoryBytes(addr uintptr, sz int) (m memoryMap) {
	m = memoryMap{}
	dh := m.header()
	dh.Data = addr
	dh.Len = sz
	dh.Cap = dh.Len
	return
}

func handleWmCopyMessage(cdata *COPYDATASTRUCT) {
	if cdata.dwData != AGENT_COPYDATA_ID {
		return //not a putty message
	}

	log.Println("Received a PUTTY message")

	m := getMemoryBytes(cdata.lpData, int(cdata.cbData-1)) //remove \0

	var mapname string = string(m[:cdata.cbData-1])

	log.Println("Using mapname:", mapname)

	const FILE_MAP_ALL_ACCESS = 0xF001F

	h := OpenFileMapping(FILE_MAP_ALL_ACCESS, 0, mapname)
	if h == 0 {
		log.Println("Failed to OpenFileMapping")
		return
	}
	defer syscall.CloseHandle(h)

	addr, errno := syscall.MapViewOfFile(h, uint32(syscall.FILE_MAP_WRITE), 0, 0, 0)
	if addr == 0 {
		log.Println("Failed:", os.NewSyscallError("MapViewOfFile", errno))
		return
	}

	//read message size
	m = getMemoryBytes(addr, 4)

	//decode BigEndian size
	var ln int32
	buf := bytes.NewBuffer(m)
	binary.Read(buf, binary.BigEndian, &ln)

	//Read ssh-agent message based on ln
	m = getMemoryBytes(addr, int(ln)+4)

	log.Println("addr:", addr, " length:", ln)

	var out bytes.Buffer
	rw := NewReadWriter(bytes.NewBuffer(m), &out)

	if err := sshAgent.ProcessRequest(rw); err != nil {
		fmt.Println("Failed:", err)
		return
	}

	m = getMemoryBytes(addr, out.Len())

	log.Printf("Writing %v bytes to memory\n", out.Len())

	//Copy bytes to shared memory
	outbytes := out.Bytes()
	for i := 0; i < out.Len(); i++ {
		m[i] = outbytes[i]
	}
}
