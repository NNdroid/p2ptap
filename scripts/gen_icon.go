package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
)

func main() {
	const width = 32
	const height = 32

	bgR, bgG, bgB := byte(0x10), byte(0xb9), byte(0x81) // Emerald Green

	bgraPixels := make([]byte, width*height*4)

	// Bottom-up scanlines for Windows DIB BMP ICO format
	for y := 0; y < height; y++ {
		invY := height - 1 - y
		for x := 0; x < width; x++ {
			pixelIdx := (invY*width + x) * 4

			dxBg := x - 16
			dyBg := y - 16
			distSqBg := dxBg*dxBg + dyBg*dyBg

			if distSqBg > 15*15 {
				// Transparent
				bgraPixels[pixelIdx+0] = 0
				bgraPixels[pixelIdx+1] = 0
				bgraPixels[pixelIdx+2] = 0
				bgraPixels[pixelIdx+3] = 0
				continue
			}

			r, g, b, a := bgR, bgG, bgB, byte(255)

			// 1. Goose Body
			dxBody := x - 15
			dyBody := y - 19
			distSqBody := dxBody*dxBody + dyBody*dyBody

			// 2. Goose Head
			dxHead := x - 14
			dyHead := y - 11
			distSqHead := dxHead*dxHead + dyHead*dyHead

			// 3. Beak
			dxBeak := x - 21
			dyBeak := y - 12
			distSqBeak := dxBeak*dxBeak + dyBeak*dyBeak

			// 4. Eye
			dxEye := x - 17
			dyEye := y - 10
			distSqEye := dxEye*dxEye + dyEye*dyEye

			if distSqEye <= 1 {
				r, g, b = 15, 23, 42
			} else if distSqBeak <= 5 && x >= 19 {
				r, g, b = 249, 115, 22
			} else if distSqHead <= 28 || distSqBody <= 55 {
				r, g, b = 255, 255, 255
			} else if distSqBg > 14*14 {
				a = 180
			}

			bgraPixels[pixelIdx+0] = b
			bgraPixels[pixelIdx+1] = g
			bgraPixels[pixelIdx+2] = r
			bgraPixels[pixelIdx+3] = a
		}
	}

	andMask := make([]byte, width*height/8) // 128 bytes 00

	imageSize := uint32(40 + len(bgraPixels) + len(andMask))

	var icoBuf bytes.Buffer
	// ICONDIR (6 bytes)
	binary.Write(&icoBuf, binary.LittleEndian, uint16(0)) // Reserved
	binary.Write(&icoBuf, binary.LittleEndian, uint16(1)) // Type ICO
	binary.Write(&icoBuf, binary.LittleEndian, uint16(1)) // Image Count

	// ICONDIRENTRY (16 bytes)
	icoBuf.WriteByte(byte(width))
	icoBuf.WriteByte(byte(height))
	icoBuf.WriteByte(0) // Colors
	icoBuf.WriteByte(0) // Reserved
	binary.Write(&icoBuf, binary.LittleEndian, uint16(1))
	binary.Write(&icoBuf, binary.LittleEndian, uint16(32))
	binary.Write(&icoBuf, binary.LittleEndian, imageSize)
	binary.Write(&icoBuf, binary.LittleEndian, uint32(22))

	// BITMAPINFOHEADER (40 bytes)
	binary.Write(&icoBuf, binary.LittleEndian, uint32(40))
	binary.Write(&icoBuf, binary.LittleEndian, int32(width))
	binary.Write(&icoBuf, binary.LittleEndian, int32(height*2)) // Double height for AND mask
	binary.Write(&icoBuf, binary.LittleEndian, uint16(1))
	binary.Write(&icoBuf, binary.LittleEndian, uint16(32))
	binary.Write(&icoBuf, binary.LittleEndian, uint32(0)) // BI_RGB
	binary.Write(&icoBuf, binary.LittleEndian, uint32(len(bgraPixels)))
	binary.Write(&icoBuf, binary.LittleEndian, int32(0))
	binary.Write(&icoBuf, binary.LittleEndian, int32(0))
	binary.Write(&icoBuf, binary.LittleEndian, uint32(0))
	binary.Write(&icoBuf, binary.LittleEndian, uint32(0))

	icoBuf.Write(bgraPixels)
	icoBuf.Write(andMask)

	_ = os.WriteFile("app.ico", icoBuf.Bytes(), 0644)
	_ = os.WriteFile("cmd/p2ptap-tray/icon.ico", icoBuf.Bytes(), 0644)

	manifestContent := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <assemblyIdentity version="1.0.0.0" processorArchitecture="*" name="p2ptap-tray" type="win32"/>
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v2">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="asInvoker" uiAccess="false"/>
      </requestedPrivileges>
    </security>
  </trustInfo>
</assembly>`
	_ = os.WriteFile("app.manifest", []byte(manifestContent), 0644)

	rcContent := "1 24 \"app.manifest\"\n1 ICON \"app.ico\"\n"
	_ = os.WriteFile("app.rc", []byte(rcContent), 0644)

	_ = os.Remove("cmd/p2ptap-tray/rsrc_windows_amd64.syso")

	// Compile for amd64
	cmd64 := exec.Command("windres", "-i", "app.rc", "-O", "coff", "-F", "pe-x86-64", "-o", "cmd/p2ptap-tray/p2ptap-tray_windows_amd64.syso")
	if out, err := cmd64.CombinedOutput(); err != nil {
		fmt.Printf("windres amd64 error: %v (%s)\n", err, string(out))
	} else {
		fmt.Println("[+] Successfully generated cmd/p2ptap-tray/p2ptap-tray_windows_amd64.syso!")
	}

	// Compile for 386
	cmd386 := exec.Command("windres", "-i", "app.rc", "-O", "coff", "-F", "pe-i386", "-o", "cmd/p2ptap-tray/p2ptap-tray_windows_386.syso")
	if out, err := cmd386.CombinedOutput(); err != nil {
		fmt.Printf("windres 386 error: %v (%s)\n", err, string(out))
	} else {
		fmt.Println("[+] Successfully generated cmd/p2ptap-tray/p2ptap-tray_windows_386.syso!")
	}
}
