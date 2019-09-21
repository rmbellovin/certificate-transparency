package main

import "net/http"
import "flag"
import "strings"
import "github.com/gorilla/mux"
import "log"
import "./ctl_monitor-lib"
import "strconv"
import "github.com/prometheus/client_golang/prometheus/promhttp"

// custom command-line flag types require functions Set() and String()
type list_flags []string

func (list *list_flags) Set(value string) error {
    
    *list = append(*list, value)
    return nil

}   

func (list *list_flags) String() string {

    return strings.Join([]string(*list), " ")

}

func main() {

    ctl_host := flag.String("ctl", "", "certificate transparency log to monitor (required)")
    var hostnames list_flags
    flag.Var(&hostnames, "hostname", "hostname to monitor (more than one may be specified)")
    verbose := flag.Bool("verbose", false, "verbose output to log; defaults to false")
    no_auto := flag.Bool("no-auto", false, "don't start actively monitoring; defaults to false")
    build := flag.Bool("build", false, "automatically build a database on start-up; defaults to false")
    no_delete := flag.Bool("no-delete", false, "do not clear any existing database on start-up; defaults to false")
    non_strict := flag.Bool("non-strict", false, "add certificates to the database if they contain a hostname as a substring; defaults to false")
    port := flag.Int("port", 8000, "port to listen on; defaults to 8000")
    flag.Parse()

    if *ctl_host == "" {
        log.Fatalln("command-line options: \n [--hostname HOSTNAME] \n \t hostname to monitor (more than one may be specified) \n [--verbose] \n \t verbose output to log; defaults to false \n [--port PORT] \n \t port to listen on; defaults to 8000 \n [--build] \n \t automatically build a database on start-up; defaults to false \n --ctl CTL \n \t certificate transparency log to monitor (required)")
    }


// initialize new controller
    if (*ctl_host)[len(*ctl_host)-1] != "/"[0] {
        *ctl_host = *ctl_host + "/"
    }

    controller, err := ctl_monitor_lib.NewController(*ctl_host, hostnames, *verbose, *no_auto, *build, *no_delete, *non_strict)
    if err != nil {
        log.Fatalln(err)
    }


// start new router and register handlers
    r := mux.NewRouter()
    r.HandleFunc("/", controller.Status)
    r.HandleFunc("/Add", controller.AddHostname).Queries("hostname", "{hostname}")
    r.HandleFunc("/Remove", controller.RemoveHostname).Queries("hostname", "{hostname}")
    r.HandleFunc("/ListHostnames", controller.ListHostnames)
    r.HandleFunc("/ListCertificates", controller.ListCertificates).Queries("hostname", "{hostname}")
    r.HandleFunc("/Start", controller.Start)
    r.HandleFunc("/Stop", controller.Stop)
    r.HandleFunc("/Build", controller.BuildDatabase)
    r.HandleFunc("/Check", controller.Check)
    r.HandleFunc("/Delete", controller.DeleteHostname).Queries("hostname", "{hostname}")

    r.Handle("/metrics", promhttp.Handler())
    http.ListenAndServe(":" + strconv.Itoa(*port), r)

}
