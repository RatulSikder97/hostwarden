package compromise

import (
	"regexp"
	"strings"
)

// indicator is a regular expression that marks a command line or config line
// as a likely compromise artifact.
type indicator struct {
	re     *regexp.Regexp
	reason string
}

// minerNames are process/binary names of common Monero/ETH miners and the
// droppers that install them.
var minerNames = []string{
	"xmrig", "xmr-stak", "xmrig-notls", "kdevtmpfsi", "kinsing", "minerd", "cpuminer", "ccminer",
	"nbminer", "t-rex", "lolminer", "phoenixminer", "ethminer", "nanominer", "srbminer", "srbminer-multi",
	"teamredminer", "bminer", "xmrstak", "moneroocean", "c3pool", "sysupdate", "networkservice",
}

var minerNameRe = regexp.MustCompile(`(?i)(^|[/\s\[])(` + strings.Join(quoteAll(minerNames), "|") + `)($|[\s\]./:-])`)

var (
	stratumRe   = regexp.MustCompile(`(?i)stratum\+(tcp|ssl|tls)://`)
	minerArgsRe = regexp.MustCompile(`(?i)--donate-level|--cpu-max-threads-hint|\brandomx\b|\brx/0\b|\bcryptonight\b`)
)

var commandIndicators = []indicator{
	{regexp.MustCompile(`(?i)\b(curl|wget)\b[^|;&]*\|\s*(sudo\s+)?(ba|da|z)?sh\b`), "downloads a remote script and pipes it to a shell"},
	{regexp.MustCompile(`(?i)\bbase64\s+(-d|--decode)\b`), "decodes an embedded base64 payload"},
	{stratumRe, "references a mining pool (stratum) URL"},
	{regexp.MustCompile(`/dev/tcp/\S+/\d+`), "opens a /dev/tcp reverse connection"},
	{regexp.MustCompile(`(?i)\b(nc|ncat|netcat)\b.*\s-e\s`), "spawns a netcat reverse shell"},
	{regexp.MustCompile(`(?i)\bchattr\s+[+-]i\b`), "toggles the immutable attribute (anti-removal persistence)"},
	{regexp.MustCompile(`(^|[;&|('"]\s*|\b(sh|bash|dash|nohup|exec|setsid|env)\s+)/(tmp|var/tmp|dev/shm|run/shm)/\S+`), "executes from a world-writable directory"},
	{minerArgsRe, "uses crypto-miner arguments"},
	{minerNameRe, "references a known crypto-miner binary"},
}

// suspiciousReasons returns every indicator reason that matches s.
func suspiciousReasons(s string) []string {
	var out []string
	for _, ind := range commandIndicators {
		if ind.re.MatchString(s) {
			out = append(out, ind.reason)
		}
	}
	return out
}

func quoteAll(ss []string) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = regexp.QuoteMeta(s)
	}
	return out
}
