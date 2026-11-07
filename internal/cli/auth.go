package cli

import (
	"bytes"
	"fmt"
	"io"
	"os"

	"golang.org/x/term"
	"gonet/internal/auth"
)

func runAuth(args []string, stdout, stderr io.Writer) int {
	if len(args) == 1 && args[0] == "generate-agent-token" {
		token, digest, err := auth.GenerateAgentToken()
		if err != nil {
			fmt.Fprintln(stderr, "auth: secure token generation failed")
			return ExitNoResult
		}
		fmt.Fprintln(stderr, "仅本次显示原始只读 Token；请存入客户端受控环境，勿复制到日志或仓库。")
		fmt.Fprintf(stdout, "GONET_AGENT_TOKEN=%s\nGONET_AGENT_READ_TOKEN_SHA256=%s\n", token, digest)
		return ExitOK
	}
	if len(args) != 1 || args[0] != "hash-password" {
		fmt.Fprintln(stderr, "usage: gonet auth hash-password | generate-agent-token")
		return ExitUsage
	}
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		fmt.Fprintln(stderr, "auth: 请在交互终端运行，密码不接受参数或管道输入")
		return ExitUsage
	}
	return hashPasswordPrompt(stdout, stderr, func() ([]byte, error) { return term.ReadPassword(fd) })
}
func hashPasswordPrompt(stdout, stderr io.Writer, read func() ([]byte, error)) int {
	fmt.Fprint(stderr, "管理员密码（至少 12 个字符，最多 72 UTF-8 字节）：")
	password, err := read()
	fmt.Fprintln(stderr)
	defer clear(password)
	if err != nil {
		fmt.Fprintln(stderr, "auth: 无法读取密码")
		return ExitUsage
	}
	if err = auth.ValidatePassword(password); err != nil {
		fmt.Fprintln(stderr, "auth:", err)
		return ExitUsage
	}
	fmt.Fprint(stderr, "再次输入密码：")
	confirmation, err := read()
	fmt.Fprintln(stderr)
	defer clear(confirmation)
	if err != nil || !bytes.Equal(password, confirmation) {
		fmt.Fprintln(stderr, "auth: 两次密码不一致或输入失败")
		return ExitUsage
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		fmt.Fprintln(stderr, "auth: 密码哈希生成失败")
		return ExitNoResult
	}
	fmt.Fprintln(stdout, string(hash))
	return ExitOK
}
