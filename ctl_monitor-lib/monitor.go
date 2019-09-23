package ctl_monitor_lib

import "fmt"
import "log"
import "database/sql"
import _ "github.com/mattn/go-sqlite3"
import "time"
import "regexp"
import "strings"
import "github.com/prometheus/client_golang/prometheus"

var REQUEST_SIZE uint64 = 1024
var SLEEP time.Duration = 5 * time.Minute

type db_row struct {
    timestamp uint64
    common_name string
    cert string
    logentrytype string
}

type Monitor struct {
    ctl_host string
    hostnames []string
    tree_head Signed_tree_head
    database *sql.DB
    certificate_metrics *prometheus.CounterVec
    Signal chan int
    VERBOSE bool
    NON_STRICT bool
}

func NewMonitor(ctl_host string, hostnames []string, verbose bool, no_delete bool, non_strict bool) (*Monitor, error) {

    var monitor Monitor

    monitor.VERBOSE = verbose

    if monitor.VERBOSE { fmt.Printf("Initializing new CTL monitor.\n") }

    monitor.ctl_host = ctl_host
    if monitor.VERBOSE { fmt.Printf("Certificate transparency log: %s\n", monitor.ctl_host) }
    monitor.hostnames = hostnames
    if monitor.VERBOSE { fmt.Printf("Hostnames: \n%v\n", hostnames) }

    monitor.Signal = make(chan int)

    sth, err := getSTH(ctl_host)
    if err != nil {
        log.Println("Error getting signed tree head.")
        return &monitor, err
    }
    monitor.tree_head = sth
    if monitor.VERBOSE { fmt.Printf("Tree head: \n%v\n", monitor.tree_head) }

// prepare database
    database_name := makeDBName(ctl_host)
    monitor.database, err = prepareDatabase(database_name, monitor.VERBOSE, no_delete)
    if err != nil {
        log.Println("Error initializing database.")
        return &monitor, err
    }

// prepare metrics
    monitor.certificate_metrics = prepareMetrics(monitor.hostnames)
    prometheus.MustRegister(monitor.certificate_metrics)

    monitor.NON_STRICT = non_strict

    return &monitor, err

}

func (m *Monitor) CTL_host() string {

    return m.ctl_host

}

// add hostnames
func (m *Monitor) addHostnames(new_hostnames []string) {

    for _, entry := range new_hostnames {
// if a new hostname isn't already in the hostname list, append it
        if index(m.hostnames, entry) == -1 {
            m.hostnames = append(m.hostnames, entry)
        }
        
// create new counters for the new hostname, one for X509 entries, one for PreCert entries
        m.certificate_metrics.WithLabelValues(entry, "X509")
        m.certificate_metrics.WithLabelValues(entry, "PreCert")
    }


    if m.VERBOSE { fmt.Printf("Hostname list:%v\n", m.hostnames) }

}

// remove hostname
func (m *Monitor) removeHostname(hostname string) {

    if m.VERBOSE { fmt.Printf("Removing %s from hostnames\n", hostname) }

    for i, entry := range m.hostnames {
        if entry == hostname {
            m.hostnames = append(m.hostnames[:i],m.hostnames[i+1:]...)
        }
    }
    
    if m.VERBOSE { fmt.Println("Hostname list:\n", m.hostnames) }

}

// list hostnames
func (m *Monitor) getHostnames() []string {

    return m.hostnames

}

// return tree head
func (m *Monitor) getTreeHead() Signed_tree_head {

    return m.tree_head

}

// return timestamp of treehead
func (m *Monitor) getTimestamp() uint64 {
    
    return m.tree_head.Timestamp

}

// return treesize
func (m *Monitor) getTreeSize() uint64 {

    return m.tree_head.Tree_size

}

// get timestamps and certificates for specified hostname
func (m *Monitor) listCerts(hostname string) []db_row {

// query the database
    rows, err := m.database.Query("SELECT DISTINCT timestamp, certificate, logentrytype FROM certificates WHERE commonname = ?", hostname)
    if err != nil {
        log.Println("Error accessing database.")
        log.Fatalln(err)
    }
    defer rows.Close()

// scan through the results and append each one to a list of results
    var results []db_row
    var row db_row
    for rows.Next() {
        err = rows.Scan(&row.timestamp, &row.cert, &row.logentrytype)
        if err != nil {
            log.Println("Error accessing database row.")
            log.Fatalln(err)
        }
        results = append(results, row)
    }

// return results
    return results

}

// search entire ct log and build database
func (m *Monitor) buildDB() {

// add all entries
    if m.VERBOSE { fmt.Printf("Building database of certificates for hostnames %v\n", m.hostnames) }
    m.addEntries(0, m.tree_head.Tree_size-1)

}

// search ct log from entry 'start' to entry 'end' and add the appropriate certificates to the database.  if 'end' >= 'tree_size', replaces 'end' with 'tree_size'-1
func (m *Monitor) addEntries(start uint64, end uint64) {

// prepare a statement to insert results into the database
    if m.VERBOSE { fmt.Printf("Searching %s between entries %d and %d for certificates for hostnames %v\n", m.ctl_host, start, end, m.hostnames) }
    statement, err := m.database.Prepare("INSERT OR IGNORE INTO certificates (timestamp, commonname, certificate, logentrytype) VALUES (?, ?, ?, ?)")
    if err != nil {
        log.Fatalln(err)
    }
    defer statement.Close()

    var entries []rawEntry
    var leaf MerkleTreeLeaf
    var timestamp uint64
    var common_name string
// make sure we don't go past the end of the CT log
    max := min(m.tree_head.Tree_size - 1, end)

// certificate logs are big; only fetch a few entries at a time
    for ; start <= max; start += REQUEST_SIZE {
        if m.VERBOSE { fmt.Printf("Checking entries starting at %d\n", start) }
// request at most REQUEST_SIZE entries from the CT log
        finish := min(start+REQUEST_SIZE, max)
        entries = getEntries(m.ctl_host, start, finish)

// parse each entry the CT log returned
        for _, entry := range entries {
// if the entry is malformed, skip it and go on to the next one
            leaf, err = parseLeafInput(entry)
            if err != nil {
                log.Println(err)
                continue
            }
            timestamp = leaf.Timestamp

// if the LogEntryType is neither 0 (X509) nor 1 (PreCert), skip it and go on to the next entry
            if leaf.LogEntryType != 0 && leaf.LogEntryType != 1 {
                continue
            }

// parse the certificate entry and extract the commonname field.  if it's malformed, skip it and go on to the next entry
            common_name, err = getCommonname(leaf)
            if err != nil {
                log.Println(err)
                continue
            }
            if m.VERBOSE { fmt.Println(timestamp, common_name, LOG_ENTRY_TYPE_MAP[leaf.LogEntryType]) }

// check whether the commonname is one of the hostnames we're monitoring for
            var hostname string
            var i int
            if m.NON_STRICT {
                hostname, i = indexNonStrict(m.hostnames, common_name)
            } else {
                hostname = common_name
                i = index(m.hostnames, common_name)
            }

// if it is, add the timestamp, certificate type, commonname, and certificate type to the database, and increment the appropriate metric
            if i != -1 {
                if m.VERBOSE { fmt.Println("Adding", timestamp, common_name, leaf.Entry, LOG_ENTRY_TYPE_MAP[leaf.LogEntryType]) }
                results, _ := statement.Exec(timestamp, common_name, leaf.Entry, LOG_ENTRY_TYPE_MAP[leaf.LogEntryType])
                rows_added, _ := results.RowsAffected()

                metric := m.certificate_metrics.WithLabelValues(hostname, LOG_ENTRY_TYPE_MAP[leaf.LogEntryType])
                metric.Add(float64(rows_added))
            }        
        }
    }

    if m.VERBOSE { fmt.Printf("Done searching %s for certificates for hostnames %v\n", m.ctl_host, m.hostnames) }

}

// wakes up every SLEEP minutes to check for new entries.  
func (m *Monitor) Activate(signal chan int) {

    if m.VERBOSE { fmt.Printf("Monitoring certificate transparency log %s for certificates for the following hostnames:\n%v\n", m.ctl_host, m.hostnames) }
    loop:
    for true {
        
        m.Check()

// function exits if it receives a signal from the Stop() function
        select {
            case <- signal: break loop
            case <- time.After(SLEEP): if m.VERBOSE { fmt.Printf("Waking up\n") }
        }
    }

}

// check for new certificates
func (m *Monitor) Check() {

// get the new signed tree head; if there's a problem, print and error and return
    new_sth, err := getSTH(m.ctl_host)
    if err != nil {
        log.Println("Error getting a new signed tree head")
        log.Println(err)
        return
    }

    if new_sth.Tree_size != m.tree_head.Tree_size {
        if m.VERBOSE { fmt.Printf("New entries found; %s now contains %d entries\n", m.ctl_host, new_sth.Tree_size) }

        m.addEntries(m.tree_head.Tree_size, new_sth.Tree_size-1)

        m.tree_head = new_sth
    }

}

// stop automatically checking for new entries every SLEEP
func (m *Monitor) Stop(signal chan int) {

    if m.VERBOSE { fmt.Printf("No longer actively monitoring %s\n", m.ctl_host) }
    signal <- 1

}

// deletes database entries for specified hostname
func (m *Monitor) deleteDBEntries(hostname string) {

    if m.VERBOSE { fmt.Printf("Deleting database entries for hostname %s.", hostname) }
// prepare a statement to delete entries from the database
    statement, err := m.database.Prepare("DELETE FROM certificates WHERE commonname = ?")
    if err != nil {
        log.Println("Database error while attempting to delete entries for hostname " + hostname)
        log.Println(err)
        return
    }
    statement.Exec(hostname)
    statement.Close()

    m.certificate_metrics.DeleteLabelValues(hostname, "X509")
    m.certificate_metrics.DeleteLabelValues(hostname, "PreCert")

}

// make a database name out of ctl_host
func makeDBName(ctl_host string) string {

    name := ctl_host + ".db"

    re := regexp.MustCompile(`http.://`)
    name = re.ReplaceAllString(name, "")
    re = regexp.MustCompile(`/`)
    name = re.ReplaceAllString(name, ".")
    re = regexp.MustCompile(`\.+`)
    name = re.ReplaceAllString(name, ".")

    name = "./" + name

    return name

}

// finds the index of the first occurence of 'word' as a superstring in an array of strings, and returns the substring and the index.  returns "", -1 if word does not appear in array
func indexNonStrict(array []string, word string) (string, int) {

    for i, entry := range array {
        if strings.Contains(word, entry) {
            return entry, i
        }
    }

    return "", -1

}

// finds the index of the first occurence of 'word' in an array of strings.  returns -1 if word does not appear in array
func index(array []string, word string) int {

    for i, entry := range array {
        if word == entry {
            return i
        }
    }

    return -1

}

// min of two uint64's
func min(a uint64, b uint64) uint64 {
    if a < b {
        return a
    }
    return b
}

// prepare database
func prepareDatabase(database_name string, verbose bool, no_delete bool) (*sql.DB, error) {

    db, err := sql.Open("sqlite3", database_name)
    if err != nil {
        log.Fatalln(err)
        return db, err
    }

    if verbose { fmt.Printf("Results stored in sqlite3 database %s\n", database_name) }

// clear the database if it wasn't empty, unless no_delete is set
    if !no_delete {
        statement, _ := db.Prepare("DROP TABLE IF EXISTS certificates")
        statement.Exec()
        statement.Close()
    }

// create a table with columns 'timestamp', 'commonname', 'certificate', 'logentrytype', and require each row to be unique
    statement, _ := db.Prepare("CREATE TABLE IF NOT EXISTS certificates (timestamp INTEGER, commonname TEXT, certificate TEXT, logentrytype TEXT, PRIMARY KEY (timestamp, commonname, certificate, logentrytype) )")
    statement.Exec()
    statement.Close()

    if verbose { fmt.Println("Table 'certificates' created with columns 'timestamp', 'commonname', 'certificate', and 'logentrytype'") }

// delete any rows from the new table.  this shouldn't do anything
    if !no_delete {
        statement, _ := db.Prepare("DELETE FROM certificates")
        statement.Exec()
        statement.Close()
        if verbose { fmt.Println("Table 'certificates' now empty") } 
    }

    return db, err

}

// prepare metrics
func prepareMetrics(hostnames []string) *prometheus.CounterVec {

// initialize a vector of counters, indexed by hostname and log entry type
    countervec := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "certificate_metric",
		Help: "Counts certificates added to the database.",
	}, []string{"hostname", "log_entry_type"})

    for _, entry := range hostnames {
        countervec.WithLabelValues(entry, "X509")
        countervec.WithLabelValues(entry, "PreCert")
    }

    return countervec

}
