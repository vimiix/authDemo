// +build windows

package auth

import (
	"syscall"
	"unsafe"
)

// 下面的常量定义在 Winbase.h 头文件中
// logon type
const (
	LOGON32_LOGON_INTERACTIVE = 2
)

// logon provider
const (
	LOGON32_PROVIDER_DEFAULT = 0
)

var (
	modAdvApi32    = syscall.NewLazyDLL("advapi32.dll")
	procLogonUserW = modAdvApi32.NewProc("LogonUserW")
)

func Auth(user, password string) error {
	_, err := logon(user, "", password)
	return err
}

func logon(username string, domain string, password string) (syscall.Token, error) {
	var token syscall.Token
	err := logonUserW(
		syscall.StringToUTF16Ptr(username),
		syscall.StringToUTF16Ptr(domain),
		syscall.StringToUTF16Ptr(password),
		LOGON32_LOGON_INTERACTIVE,
		LOGON32_PROVIDER_DEFAULT,
		&token,
	)
	if err != nil {
		return 0, err
	}

	return token, nil
}

func logonUserW(username *uint16, domain *uint16, password *uint16, logonType uint32,
	logonProvider uint32, outToken *syscall.Token) error {
	ret, _, err := syscall.Syscall6(
		procLogonUserW.Addr(),
		6,
		uintptr(unsafe.Pointer(username)),
		uintptr(unsafe.Pointer(domain)),
		uintptr(unsafe.Pointer(password)),
		uintptr(logonType),
		uintptr(logonProvider),
		uintptr(unsafe.Pointer(outToken)),
	)
	if ret == 0 {
		if err == 0 {
			err = syscall.EINVAL
		}
		return err
	}
	return nil
}
