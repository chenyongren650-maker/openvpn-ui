package services

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"syscall"
	"time"
)

const (
	defaultOATHSecretsMaxSize = 1024 * 1024
	defaultOATHLineMaxSize    = 4096
	defaultQRCodeMaxSize      = 4 * 1024 * 1024
	totpSecretByteLength      = 20
	totpTimeStepSeconds       = 30
	totpCodeDigits            = 6
)

var tfaNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@-]{0,127}$`)

type oathIdentity struct {
	TFAName string
	HexSeed string
}

type totpQRCodeGenerator interface {
	Generate(context.Context, string, *os.File) error
}

type commandTOTPQRCodeGenerator struct {
	binary string
}

func (g commandTOTPQRCodeGenerator) Generate(
	ctx context.Context,
	payload string,
	output *os.File,
) error {
	if g.binary == "" || output == nil {
		return errors.New("TOTP QR code generator is unavailable")
	}
	command := exec.CommandContext(ctx, g.binary, payload)
	command.Stdout = output
	command.Stderr = io.Discard
	if err := command.Run(); err != nil {
		return errors.New("TOTP QR code generation failed")
	}
	return nil
}

// HexSeedToBase32 converts an oath.secrets HEX seed to RFC 4648 Base32
// without padding. It never includes the input in returned errors.
func HexSeedToBase32(hexSeed string) (string, error) {
	if hexSeed == "" || len(hexSeed)%2 != 0 {
		return "", errors.New("TOTP seed format is invalid")
	}
	decoded, err := hex.DecodeString(hexSeed)
	if err != nil || len(decoded) == 0 {
		return "", errors.New("TOTP seed format is invalid")
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(decoded), nil
}

func parseOATHSecrets(data []byte) ([]oathIdentity, error) {
	if len(data) == 0 || len(data) > defaultOATHSecretsMaxSize {
		return nil, errors.New("TOTP identity file is invalid")
	}
	lines := bytes.Split(data, []byte{'\n'})
	identities := make([]oathIdentity, 0, len(lines))
	seen := make(map[string]struct{}, len(lines))
	for lineIndex, line := range lines {
		if len(line) == 0 && lineIndex == len(lines)-1 {
			continue
		}
		if len(line) == 0 || len(line) > defaultOATHLineMaxSize ||
			bytes.IndexByte(line, '\r') >= 0 ||
			bytes.IndexByte(line, 0) >= 0 ||
			bytes.Count(line, []byte{':'}) != 1 {
			return nil, errors.New("TOTP identity file is invalid")
		}
		separator := bytes.IndexByte(line, ':')
		tfaName := string(line[:separator])
		hexSeed := string(line[separator+1:])
		if !tfaNamePattern.MatchString(tfaName) {
			return nil, errors.New("TOTP identity file is invalid")
		}
		if _, err := HexSeedToBase32(hexSeed); err != nil {
			return nil, errors.New("TOTP identity file is invalid")
		}
		if _, exists := seen[tfaName]; exists {
			return nil, errors.New("TOTP identity file contains duplicate identities")
		}
		seen[tfaName] = struct{}{}
		identities = append(identities, oathIdentity{
			TFAName: tfaName,
			HexSeed: hexSeed,
		})
	}
	if len(identities) == 0 {
		return nil, errors.New("TOTP identity file is invalid")
	}
	return identities, nil
}

func findOATHIdentity(
	identities []oathIdentity,
	tfaName string,
) (oathIdentity, error) {
	if !tfaNamePattern.MatchString(tfaName) {
		return oathIdentity{}, errors.New("TOTP identity is invalid")
	}
	for _, identity := range identities {
		if identity.TFAName == tfaName {
			return identity, nil
		}
	}
	return oathIdentity{}, errors.New("TOTP identity was not found")
}

func replaceOATHIdentity(
	identities []oathIdentity,
	tfaName string,
	hexSeed string,
) ([]byte, error) {
	if _, err := HexSeedToBase32(hexSeed); err != nil {
		return nil, err
	}
	replaced := false
	var buffer bytes.Buffer
	for _, identity := range identities {
		if identity.TFAName == tfaName {
			if replaced {
				return nil, errors.New("TOTP identity file contains duplicate identities")
			}
			identity.HexSeed = hexSeed
			replaced = true
		}
		buffer.WriteString(identity.TFAName)
		buffer.WriteByte(':')
		buffer.WriteString(identity.HexSeed)
		buffer.WriteByte('\n')
	}
	if !replaced {
		return nil, errors.New("TOTP identity was not found")
	}
	return buffer.Bytes(), nil
}

func generateTOTPCode(seed []byte, at time.Time) (string, error) {
	if len(seed) == 0 || at.Unix() < 0 {
		return "", errors.New("TOTP input is invalid")
	}
	counter := uint64(at.Unix() / totpTimeStepSeconds)
	var counterBytes [8]byte
	binary.BigEndian.PutUint64(counterBytes[:], counter)
	mac := hmac.New(sha1.New, seed)
	_, _ = mac.Write(counterBytes[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := (uint32(sum[offset])&0x7f)<<24 |
		uint32(sum[offset+1])<<16 |
		uint32(sum[offset+2])<<8 |
		uint32(sum[offset+3])
	code := value % 1_000_000
	return fmt.Sprintf("%0"+strconv.Itoa(totpCodeDigits)+"d", code), nil
}

func readSecureRegularFile(
	path string,
	maxSize int64,
	requirePrivatePermissions bool,
) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, errors.New("sensitive file is not a regular file")
	}
	if requirePrivatePermissions && info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("sensitive file permissions are too broad")
	}
	if info.Size() < 0 || info.Size() > maxSize {
		return nil, errors.New("sensitive file size is invalid")
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !openedInfo.Mode().IsRegular() ||
		!os.SameFile(info, openedInfo) ||
		(requirePrivatePermissions && openedInfo.Mode().Perm()&0o077 != 0) {
		return nil, errors.New("sensitive file changed during validation")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxSize+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxSize {
		return nil, errors.New("sensitive file size is invalid")
	}
	return data, nil
}

func createSecureTemporaryFile(
	directory string,
	pattern string,
) (*os.File, error) {
	file, err := os.CreateTemp(directory, pattern)
	if err != nil {
		return nil, err
	}
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		_ = os.Remove(file.Name())
		return nil, err
	}
	return file, nil
}

func writeAndSync(file *os.File, data []byte) error {
	if file == nil {
		return errors.New("temporary file is unavailable")
	}
	if _, err := file.Write(data); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	return file.Close()
}

func atomicReplaceFile(temporaryPath string, targetPath string) error {
	if filepath.Dir(temporaryPath) != filepath.Dir(targetPath) {
		return errors.New("atomic replacement requires one directory")
	}
	if err := os.Rename(temporaryPath, targetPath); err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(targetPath))
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

type totpFileLock struct {
	file *os.File
}

func acquireTOTPFileLock(
	ctx context.Context,
	lockPath string,
) (*totpFileLock, error) {
	descriptor, err := syscall.Open(
		lockPath,
		syscall.O_CREAT|syscall.O_RDWR|syscall.O_NOFOLLOW,
		0o600,
	)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(descriptor), lockPath)
	if file == nil {
		_ = syscall.Close(descriptor)
		return nil, errors.New("create TOTP file lock")
	}
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		return nil, err
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		file.Close()
		return nil, errors.New("TOTP lock path is invalid")
	}

	for {
		err = syscall.Flock(descriptor, syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return &totpFileLock{file: file}, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) &&
			!errors.Is(err, syscall.EAGAIN) {
			file.Close()
			return nil, err
		}
		select {
		case <-ctx.Done():
			file.Close()
			return nil, ctx.Err()
		case <-time.After(25 * time.Millisecond):
		}
	}
}

func (l *totpFileLock) release() {
	if l == nil || l.file == nil {
		return
	}
	_ = syscall.Flock(int(l.file.Fd()), syscall.LOCK_UN)
	_ = l.file.Close()
}
