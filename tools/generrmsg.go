package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/go-clang/v3.9/clang"
)

type ToxError struct {
	Code        int64
	Name        string
	Description string
}

var (
	errorGroups    []string
	errorCodeNames map[string][]ToxError
)

func main() {
	errorGroups = make([]string, 0)
	errorCodeNames = make(map[string][]ToxError)

	idx := clang.NewIndex(0, 1)
	defer idx.Dispose()

	tuArgs := []string{}
	if len(flag.Args()) > 0 && flag.Args()[0] == "-" {
		tuArgs = make([]string, len(flag.Args()[1:]))
		copy(tuArgs, flag.Args()[1:])
	}
	_ = tuArgs
	cmdArgs := []string{
		"-std=c99",
		"-I/usr/include/",
		"-I/usr/lib/gcc/x86_64-pc-linux-gnu/7.2.1/include"}
	tu := idx.ParseTranslationUnit("/usr/include/tox/tox.h", cmdArgs, nil, 0)
	defer tu.Dispose()

	for _, d := range tu.Diagnostics() {
		log.Println("PROBLEM:", d.Spelling())
	}

	var enumDecls = make(map[uint32]bool)
	var enumConstDecls = make(map[uint32]bool)
	var curEnumName string

	tuc := tu.TranslationUnitCursor()
	tuc.Visit(func(cursor, parent clang.Cursor) (status clang.ChildVisitResult) {
		switch cursor.Kind() {
		case clang.Cursor_EnumDecl:
			if !strings.HasPrefix(cursor.Spelling(), "TOX_ERR_") {
				break
			}
			if _, ok := enumDecls[cursor.HashCursor()]; ok {
				break
			}
			enumDecls[cursor.HashCursor()] = true
			curEnumName = cursor.Spelling()
			errorGroups = append(errorGroups, curEnumName)
		case clang.Cursor_EnumConstantDecl:
			if !strings.HasPrefix(cursor.Spelling(), "TOX_ERR_") {
				break
			}
			if _, ok := enumConstDecls[cursor.HashCursor()]; ok {
				break
			}
			enumConstDecls[cursor.HashCursor()] = true

			constComment := cursor.BriefCommentText()
			constComment = strings.Replace(constComment, "\"", "\\\"", -1)
			constName := cursor.Spelling()
			enumNameFields := strings.Split(cursor.Spelling(), "_")
			enumName := strings.Join(enumNameFields[1:len(enumNameFields)-1], "_")
			enumName = curEnumName
			constValue := cursor.EnumConstantDeclValue()
			if false {
				//log.Println(enumName, constName, constValue, constComment)
			}
			errorCodeNames[enumName] = append(errorCodeNames[enumName], ToxError{Code: constValue, Name: constName, Description: constComment})

		default:
			// log.Println(cursor.Kind().String(), cursor.Type().Kind().String(), cursor.Type().Spelling(), cursor.Spelling())
		}

		return clang.ChildVisit_Recurse
	})

	// Out file

	fmt.Fprintln(os.Stdout, "package tox")
	fmt.Fprintln(os.Stdout, "/*")
	fmt.Fprintln(os.Stdout, "#include \"tox/tox.h\"")
	fmt.Fprintln(os.Stdout, "*/")
	fmt.Fprintln(os.Stdout, `import "C"`)
	fmt.Fprintln(os.Stdout, `import "errors"`)
	fmt.Fprintln(os.Stdout, "")

	fmt.Fprintln(os.Stdout, "type ErrorGroup string")
	fmt.Fprintln(os.Stdout, "type ErrorCode int", "\n")

	fmt.Fprintln(os.Stdout, "const (")

	for _, k := range errorGroups {
		fmt.Printf("\t%s = ErrorGroup(\"%s\")\n", k, k)
	}

	fmt.Fprintln(os.Stdout, ")\n")

	fmt.Fprintln(os.Stdout, "const (")
	for _, k := range errorGroups {
		for _, v2 := range errorCodeNames[k] {
			fmt.Printf("\t%s = ErrorCode(C.%s)\n", v2.Name, v2.Name)
		}
	}
	fmt.Fprintln(os.Stdout, ")\n")

	fmt.Fprintln(os.Stdout, "type errorHolder map[ErrorGroup]map[ErrorCode]error", "\n")

	fmt.Fprintln(os.Stdout, `// ParseError returns go-style tox error`)
	fmt.Fprintln(os.Stdout, "func ParseError(group ErrorGroup, code ErrorCode) error {\n\treturn toxErrors[group][code]\n}\n")

	fmt.Fprintln(os.Stdout, "var toxErrors errorHolder", "\n")

	fmt.Fprintln(os.Stdout, "func init(){")
	fmt.Fprintln(os.Stdout, "\ttoxErrors = make(errorHolder)\n")
	for _, k := range errorGroups {
		fmt.Fprintf(os.Stdout, "\ttoxErrors[%s] = make(map[ErrorCode]error)\n", k)
	}

	fmt.Fprintln(os.Stdout, "")

	for _, k := range errorGroups {
		for _, v2 := range errorCodeNames[k] {
			if v2.Code == 0 {
				fmt.Printf("\ttoxErrors[%s][%s] = nil // %s\n", k, v2.Name, v2.Description)
			} else {
				fmt.Printf("\ttoxErrors[%s][%s] = errors.New(\"%s\")\n", k, v2.Name, v2.Description)
			}
		}
	}

	fmt.Fprintln(os.Stdout, "}\n")
}
