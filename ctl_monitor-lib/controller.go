package ctl_monitor_lib

import "fmt"
import "net/http"
import "github.com/gorilla/mux"
import "strings"
import "log"
import "time"

type Controller struct {
    monitor Monitor
}

// print status
func (c *Controller) Status(w http.ResponseWriter, r *http.Request) {

    fmt.Fprintf(w, "Monitoring the certificate transparency log %s for certificates for the following hostnames:\n %v\nThe certificate transparency log was last updated at %s and contains %d entries.\n", c.monitor.CTL_host(), c.monitor.getHostnames(), time.Unix(0, int64(c.monitor.getTimestamp())*1e6).String(), c.monitor.getTreeSize())

}

// add hostnames (comma-separated list)
func (c *Controller) AddHostname(w http.ResponseWriter, r *http.Request) {

    vars := mux.Vars(r)
    new_hostnames := vars["hostname"]

    new_hostnames_list := strings.Split(new_hostnames, ",")

    c.monitor.addHostnames(new_hostnames_list)

    fmt.Fprintf(w, "Added %v to hostname list. Now monitoring for certificates for the following list:\n %v\n", new_hostnames, c.monitor.getHostnames())

}

// remove hostname
func (c *Controller) RemoveHostname(w http.ResponseWriter, r *http.Request) {

    vars := mux.Vars(r)
    hostname := vars["hostname"]

    c.monitor.removeHostname(hostname)

    fmt.Fprintf(w, "Removed %s from hostname list. Now monitoring for certificates for the following list:\n %v\n", hostname, c.monitor.getHostnames())

}

// remove hostname and delete corresponding database entries
func (c *Controller) DeleteHostname(w http.ResponseWriter, r *http.Request) {

    vars := mux.Vars(r)
    hostname := vars["hostname"]

    c.monitor.removeHostname(hostname)

    fmt.Fprintf(w, "Removed %s from hostname list. Now monitoring for certificates for the following list:\n %v\n", hostname, c.monitor.getHostnames())

    c.monitor.deleteDBEntries(hostname)

    fmt.Fprintf(w, "Deleted certificates for %s from the database and removed the corresponding metrics", hostname)

}

// list hostnames
func (c *Controller) ListHostnames(w http.ResponseWriter, r *http.Request) {

    fmt.Fprintf(w, "%v\n", c.monitor.getHostnames())

}

// list certificates for the specified hostname
func (c *Controller) ListCertificates (w http.ResponseWriter, r *http.Request) {

    vars := mux.Vars(r)
    hostname := vars["hostname"]

    results := c.monitor.listCerts(hostname)

    fmt.Fprintf(w, "Certificates for %s:\n", hostname)

    for _, entry := range results {
        fmt.Fprintf(w, "%v\n", entry) // prettify with json?
    }

}

// initialize new controller
func NewController(ctl_host string, hostnames []string, verbose bool, no_auto bool, build bool, no_delete bool, non_strict bool) (*Controller, error) {

    var c Controller
// initialize new monitor
    monitor, err := NewMonitor(ctl_host, hostnames, verbose, no_delete, non_strict)
    if err != nil {
        log.Println("Error initializing controller.")
        return &c, err
    }
    c.monitor = *monitor

// start actively monitoring, unless --no-auto is set
    if !no_auto {
        go c.monitor.Activate(c.monitor.Signal)
    }

// if --build is set, build a database
    if build {
        go c.monitor.buildDB()
    }

    return &c, err

}

// start actively monitoring
func (c *Controller) Start(w http.ResponseWriter, r *http.Request) {

    fmt.Fprintf(w, "Starting")
    go c.monitor.Activate(c.monitor.Signal)

}

// stop actively monitoring
func (c *Controller) Stop(w http.ResponseWriter, r *http.Request) {

    fmt.Fprintf(w, "Stopping")
    c.monitor.Stop(c.monitor.Signal)

}

// search the entire CT log and build a database
func (c *Controller) BuildDatabase(w http.ResponseWriter, r *http.Request) {

    fmt.Fprintf(w, "Building a database...")
    c.monitor.buildDB()
    fmt.Fprintf(w, "Done.")

}

// check for new certificates
func (c *Controller) Check(w http.ResponseWriter, r *http.Request) {

    fmt.Fprintf(w, "Checking for new certificates.")
    c.monitor.Check()

}
