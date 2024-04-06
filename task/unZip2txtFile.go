// Package task unZip2txtFile.go
package task

import (
	"archive/zip"
	"io"
	"os"
	"strings"
)

// UnZip2txtFile 从ZIP文件中提取所有TXT文件并合并到一个新文件中
func UnZip2txtFile(zipPath string, outputPath string) error {
	// 打开ZIP文件
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return err
	}
	defer r.Close()

	// 创建输出文件
	outputFile, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer outputFile.Close()

	// 遍历ZIP文件中的每个文件
	for _, f := range r.File {
		// 检查文件是否为TXT文件
		if !strings.HasSuffix(f.Name, ".txt") {
			continue
		}

		// 打开ZIP中的文件
		rc, err := f.Open()
		if err != nil {
			return err
		}

		// 将文件内容写入输出文件
		_, err = io.Copy(outputFile, rc)
		if err != nil {
			rc.Close()
			return err
		}
		rc.Close()

		// 写入换行符以分隔每个TXT文件的内容
		_, err = outputFile.WriteString("\n")
		if err != nil {
			return err
		}
	}

	return nil
}
