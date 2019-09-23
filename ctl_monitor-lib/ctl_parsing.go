package ctl_monitor_lib


import "crypto/x509"
import "net/http"
import "log"
import "io/ioutil"
import "encoding/json"
import "strconv"
import "encoding/base64"
import "encoding/binary"
import "errors"

var GET_STH string = "ct/v1/get-sth"
var GET_ENTRIES string = "ct/v1/get-entries"
var LOG_ENTRY_TYPE_MAP map[uint16]string = map[uint16]string{0: "X509", 1: "PreCert"}

type Signed_tree_head struct {
    Tree_size uint64
    Timestamp uint64
    Sha256_root_hash string
    Tree_head_signature string
}

type Raw_entry struct {
    Leaf_input string
    Extra_data string
}

type get_entry_response struct {
    Entries []Raw_entry
}

type MerkleTreeLeaf struct {
    Version uint8
    MerkleLeafType uint8
    Timestamp uint64
    LogEntryType uint16
    Entry string
    Extra_data string
}

type certificate struct {
    Length uint32
    CertData []byte
}

// parse the first three bytes of a byte array as a uint32
func threeByteToUint32(bytes []byte) uint32 {
    padded_length := make([]byte,4)
    copy(padded_length[1:],bytes[:3])
    return binary.BigEndian.Uint32(padded_length)

}

// get entries from ctl_host between start and end (inclusive).  throws a fatal error if called with an invalid CT log url, or for an invalid range, or if there is a network problem
func getEntries(ctl_host string, start uint64, end uint64) []Raw_entry {

    if start < 0 || end < 0 {
        log.Fatalln("Invalid range: start and end must be at least 0")
    }
    if start > end {
        log.Fatalln("Invalid range: start must be at most end")
    }

    req, err := http.NewRequest("GET", ctl_host + GET_ENTRIES, nil)
    if err != nil {
	log.Fatalln(err)
    }

// initialize an empty list of entries retrieved
    var all_entries_received []Raw_entry

// the RFC allows CT logs to only return a few entries at a time, so we keep making requests
    for start <= end {

// the url to request entries between START and END (inclusive) is https://<log server>/ct/v1/get-entries?start=START&end=END, so we build it with req.URL.Query()
        q := req.URL.Query()
        q.Add("start", strconv.FormatUint(start,10))
        q.Add("end", strconv.FormatUint(end,10))
        req.URL.RawQuery = q.Encode()

        resp, err := http.Get(req.URL.String())
        if err != nil {
            log.Fatalln(err)
        }
        defer resp.Body.Close()

        body, err := ioutil.ReadAll(resp.Body)
        if err != nil {
	    log.Fatalln(err)
        }

// for some reason, go won't unmarshal data into an array of structs, but will unmarshal data into an auxiliary struct whose data is an array of structs
        var entry_array get_entry_response
        err = json.Unmarshal(body, &entry_array)
        if err != nil {
            log.Fatalln("getEntries", start, end, err)
        }

// append entries received to our list
        all_entries_received = append(all_entries_received, entry_array.Entries...)

        start += uint64(len(entry_array.Entries))
    }

    return all_entries_received

}


// get the signed tree head.  throws a fatal error if the CT log url is invalid, or there is a network issue
func getSTH(ctl_host string) (Signed_tree_head, error) {
    
    var sth Signed_tree_head

    resp, err := http.Get(ctl_host + GET_STH)
    if err != nil {
	return sth, err
    }
    defer resp.Body.Close()

    body, err := ioutil.ReadAll(resp.Body)
    if err != nil {
	return sth, err
    }

// use json to unmarshal the response into the appropriate form
    err = json.Unmarshal(body, &sth)
    if err != nil {
	return sth, err
    }

    return sth, nil

}

// take an entry and parse it as a MerkleTreeLeaf.  it's base64-encoded, so decode and parse "by hand".  the MerkleTreeLeaf.Entry field will require further processing
func parseLeafInput(entry Raw_entry) (MerkleTreeLeaf, error) {

    var leaf MerkleTreeLeaf

    leaf_input := entry.Leaf_input

    binary_decode, err := base64.StdEncoding.DecodeString(leaf_input)
    if err != nil {
	log.Println(err)
        return leaf, err
    }

    if len(binary_decode) < 12 {
        err = errors.New("Invalid entry")
        return leaf, err
    }

// the first byte is the version of the protocol. should be 0
    leaf.Version = binary_decode[0]
// the second byte gives the Merkle leaf type. should be 0
    leaf.MerkleLeafType = binary_decode[1]
// the next 8 bytes are a timestamp, in milliseconds
    leaf.Timestamp = binary.BigEndian.Uint64(binary_decode[2:10])
// the next 2 bytes give the log entry type. should be 0 or 1
    leaf.LogEntryType = binary.BigEndian.Uint16(binary_decode[10:12])
// the remainder of the leaf_input is the actual entry
    leaf.Entry = base64.StdEncoding.EncodeToString(binary_decode[12:])

// this is the extra data field from the raw entry
    leaf.Extra_data = entry.Extra_data

    return leaf, nil

}

// the MerkleTreeLeaf.Entry field is a base64 string; the first 4 characters (decoding to 3 bytes) give the length, and the rest is the certificate itself.  there seems to be some auxiliary padding at the end which has to be stripped out.  this returns a certificate, which consists of the length, plus the DER-encoded certificate itself
func parseCertEntry(leaf MerkleTreeLeaf) (certificate, error) {

    var cert_bytes []byte

    var cert certificate

    switch leaf.LogEntryType {
    case 0: 
// we have a normal x509 entry, with 3 bytes at the start giving the length
        binary_decode, err := base64.StdEncoding.DecodeString(leaf.Entry)
        if err != nil {
            log.Println(err)
	    return cert, err
        }
        if len(binary_decode)<3 {
            err = errors.New("Invalid certificate: too short")
            return cert, err
        }
        cert_bytes = binary_decode
        
    case 1:
// we have a precert entry; there are 32 bytes at the start of the extra_data field giving the length
        binary_decode, err := base64.StdEncoding.DecodeString(leaf.Extra_data)
        if err != nil {
	    log.Println(err)
            return cert, err
        }
        if len(binary_decode)<3 {
            err = errors.New("Invalid certificate entry: too short")
            return cert, err
        }
        cert_bytes = binary_decode

    default:
        err := errors.New("Unknown LogEntryType")
        return cert, err
    }

    cert.Length = threeByteToUint32(cert_bytes[0:3])

    if uint32(len(cert_bytes)) < cert.Length+3 {
        err := errors.New("Invalid certificate: too short")
        return cert, err
    }
// the actual certificate seems to be longer than it should be
    cert.CertData = cert_bytes[3:cert.Length+3]

    return cert, nil

}

// parse the DER-encoded byte sequence, and extract the commonname field.  returns the error of either parsing the leaf.Entry/leaf.Extra_data field, or of parsing the DER-encoded bytes
func getCommonname(leaf_input MerkleTreeLeaf) (string, error) {

    cert, err := parseCertEntry(leaf_input)
    if err != nil {
        log.Println(err)
        return "", err
    }
    asn_der := cert.CertData
    decoded_cert, err2 := x509.ParseCertificate(asn_der)
    if err != nil {
        log.Println(err)
        return "", err2
    }

    return decoded_cert.Subject.CommonName, nil

}
