package syslog_prase

import "github.com/miekg/dns"

var StringNumberToRcode = reverseInt16(RcodeToStringNumber)

// RcodeToStringNumber is a map of strings for each Rcode type.
var RcodeToStringNumber = map[uint16]string{
	dns.RcodeSuccess:        "0",  // NoError   - No Error                          [DNS]
	dns.RcodeFormatError:    "1",  // FormErr   - Format Error                      [DNS]
	dns.RcodeServerFailure:  "2",  // ServFail  - Server Failure                    [DNS]
	dns.RcodeNameError:      "3",  // NXDomain  - Non-Existent Domain               [DNS]
	dns.RcodeNotImplemented: "4",  // NotImp    - Not Implemented                   [DNS]
	dns.RcodeRefused:        "5",  // Refused   - Query Refused                     [DNS]
	dns.RcodeYXDomain:       "6",  // YXDomain  - Name Exists when it should not    [DNS Update]
	dns.RcodeYXRrset:        "7",  // YXRRSet   - RR Set Exists when it should not  [DNS Update]
	dns.RcodeNXRrset:        "8",  // NXRRSet   - RR Set that should exist does not [DNS Update]
	dns.RcodeNotAuth:        "9",  // NotAuth   - Server Not Authoritative for zone [DNS Update]
	dns.RcodeNotZone:        "10", // NotZone   - Name not contained in zone        [DNS Update/TSIG]
	dns.RcodeBadSig:         "16", // BADSIG    - TSIG Signature Failure            [TSIG]
	//dns.RcodeBadVers:   "16", // BADVERS   - Bad OPT Version                   [EDNS0]
	dns.RcodeBadKey:    "17", // BADKEY    - Key not recognized                [TSIG]
	dns.RcodeBadTime:   "18", // BADTIME   - Signature out of time window      [TSIG]
	dns.RcodeBadMode:   "19", // BADMODE   - Bad TKEY Mode                     [TKEY]
	dns.RcodeBadName:   "20", // BADNAME   - Duplicate key name                [TKEY]
	dns.RcodeBadAlg:    "21", // BADALG    - Algorithm not supported           [TKEY]
	dns.RcodeBadTrunc:  "22", // BADTRUNC  - Bad Truncation                    [TSIG]
	dns.RcodeBadCookie: "23", // BADCOOKIE - Bad/missing Server Cookie         [DNS Cookies]
}
