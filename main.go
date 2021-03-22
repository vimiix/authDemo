package main

import (
    "flag"
    "fmt"
    "os"

    "github.com/vimiix/authDemo/auth"
)

func main() {
    user := flag.String("u", "", "username")
    password := flag.String("p", "", "password")
    flag.Parse()

    if *user == "" || *password == "" {
        fmt.Println("Both user and password should be specify")
        fmt.Printf("Usage: %s -u [username] -p [password]\n", os.Args[0])
        return
    }


    err := auth.Auth(*user, *password)
    if err != nil {
        fmt.Printf("Auth failed.\nError message:%v\n", err)
    } else {
        fmt.Println("Auth successfully")
    }
}
