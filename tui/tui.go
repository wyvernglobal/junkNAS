// Package tui provides a terminal user interface for JunkNAS on headless systems.
// It communicates with the local junknasd REST API via the lock file.
package tui

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

// ── colour palette ────────────────────────────────────────────────────────

var (
	colBG     = tcell.NewRGBColor(13, 17, 23)
	colPanel  = tcell.NewRGBColor(22, 27, 34)
	colAccent = tcell.NewRGBColor(88, 166, 255)
	colGreen  = tcell.NewRGBColor(63, 185, 80)
	colYellow = tcell.NewRGBColor(210, 153, 34)
	colRed    = tcell.NewRGBColor(248, 81, 73)
	colText   = tcell.NewRGBColor(201, 209, 217)
	colDim    = tcell.NewRGBColor(110, 118, 129)
)

// ── API client ────────────────────────────────────────────────────────────

func apiBase() (string, error) {
	// Prefer /tmp directly — os.TempDir() can return something other than
	// /tmp when TMPDIR is set, but the daemon always writes to /tmp.
	lockPath := "/tmp/junknas.lock"
	if _, err := os.Stat(lockPath); os.IsNotExist(err) {
		// Fall back to os.TempDir() in case the daemon is on a non-Linux system.
		lockPath = filepath.Join(os.TempDir(), "junknas.lock")
	}
	data, err := os.ReadFile(lockPath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("lock file not found at %s — is junknasd running?", lockPath)
		}
		return "", fmt.Errorf("cannot read lock file %s: %w", lockPath, err)
	}
	var lock struct {
		APIPort int `json:"api_port"`
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		return "", fmt.Errorf("malformed lock file at %s: %w", lockPath, err)
	}
	if lock.APIPort == 0 {
		return "", fmt.Errorf("lock file has port=0 — daemon may still be starting")
	}
	return fmt.Sprintf("http://127.0.0.1:%d", lock.APIPort), nil
}

func apiGet(base, path string, out any) error {
	resp, err := http.Get(base + path)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return json.NewDecoder(resp.Body).Decode(out)
}

func apiPost(base, path string, payload, out any) error {
	body, _ := json.Marshal(payload)
	resp, err := http.Post(base+path, "application/json",
		strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

// ── data types ────────────────────────────────────────────────────────────

type statusResp struct {
	Self struct {
		B32         string `json:"b32"`
		Role        string `json:"role"`
		QuotaBytes  int64  `json:"quota_bytes"`
		StoragePath string `json:"storage_path"`
	} `json:"self"`
	Peers        []peerInfo `json:"peers"`
	PeerCount    int        `json:"peer_count"`
	StoragePeers int        `json:"storage_peers"`
}

type peerInfo struct {
	B32        string    `json:"b32"`
	Phrase     [3]string `json:"phrase"`
	Role       string    `json:"role"`
	QuotaBytes int64     `json:"quota_bytes"`
	LastSeen   time.Time `json:"last_seen"`
	Status     string    `json:"status"`
}

type inviteResp struct {
	B32    string    `json:"b32"`
	Phrase [3]string `json:"phrase"`
}

// ── App ───────────────────────────────────────────────────────────────────

// App is the JunkNAS terminal UI.
type App struct {
	tapp       *tview.Application
	pages      *tview.Pages
	base       string
	status     *statusResp

	// Widgets updated on refresh.
	selfBox    *tview.TextView
	statsBox   *tview.TextView
	peersTable *tview.Table
	statusBar  *tview.TextView
}

// Run starts the TUI. Blocks until the user quits.
func Run() error {
	base, err := apiBase()
	if err != nil {
		return fmt.Errorf("tui: %w", err)
	}

	a := &App{
		tapp:  tview.NewApplication(),
		pages: tview.NewPages(),
		base:  base,
	}

	a.buildDashboard()

	a.tapp.SetInputCapture(func(ev *tcell.EventKey) *tcell.EventKey {
		name, _ := a.pages.GetFrontPage()
		if name != "dashboard" {
			return ev
		}
		switch ev.Rune() {
		case 'a', 'A':
			a.showAddNode()
		case 'j', 'J':
			a.showJoinCloud()
		case 'r', 'R':
			a.refreshData()
		case 'q', 'Q':
			a.tapp.Stop()
		}
		return ev
	})

	// Queue the initial refresh to fire once the event loop is running.
	// Calling refreshData() before Run() means QueueUpdateDraw has no
	// event loop to dispatch into — the screen stays blank.
	go func() {
		time.Sleep(100 * time.Millisecond)
		a.refreshData()
	}()

	go func() {
		for range time.Tick(15 * time.Second) {
			a.refreshData()
		}
	}()

	return a.tapp.SetRoot(a.pages, true).EnableMouse(true).Run()
}

// ── dashboard layout ──────────────────────────────────────────────────────

func (a *App) buildDashboard() {
	header := tview.NewTextView().SetDynamicColors(true).SetText(
		fmt.Sprintf("[%s] ▓▓ JunkNAS[-]  [%s]Distributed Private Cloud · I2P · SMB3[-]",
			hex(colAccent), hex(colDim)),
	)
	header.SetBackgroundColor(colBG)

	selfBox := tview.NewTextView().SetDynamicColors(true)
	selfBox.SetBorder(true).
		SetTitle(" ◈ This Node ").
		SetTitleColor(colAccent).
		SetBorderColor(colPanel).
		SetBackgroundColor(colPanel)
	a.selfBox = selfBox

	statsBox := tview.NewTextView().SetDynamicColors(true)
	statsBox.SetBorder(true).
		SetTitle(" ◈ Network ").
		SetTitleColor(colAccent).
		SetBorderColor(colPanel).
		SetBackgroundColor(colPanel)
	a.statsBox = statsBox

	peersTable := tview.NewTable().
		SetBorders(false).
		SetSelectable(true, false).
		SetFixed(1, 0)
	peersTable.SetBackgroundColor(colPanel).
		SetBorder(true).
		SetTitle(" ◈ Peers ").
		SetTitleColor(colAccent).
		SetBorderColor(colPanel)
	a.peersTable = peersTable

	statusBar := tview.NewTextView().SetDynamicColors(true)
	statusBar.SetBackgroundColor(colBG)
	a.statusBar = statusBar

	actionBar := tview.NewTextView().SetDynamicColors(true).SetText(
		fmt.Sprintf(
			" [%s][A][-] (A)dd Node   [%s][J][-] (J)oin Cloud   [%s][R][-] (R)efresh   [%s][Q][-] (Q)uit",
			hex(colAccent), hex(colAccent), hex(colAccent), hex(colDim),
		),
	)
	actionBar.SetBackgroundColor(colBG)

	topRow := tview.NewFlex().SetDirection(tview.FlexColumn).
		AddItem(selfBox, 0, 3, false).
		AddItem(statsBox, 24, 0, false)

	root := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(header, 1, 0, false).
		AddItem(topRow, 9, 0, false).
		AddItem(peersTable, 0, 1, true).
		AddItem(statusBar, 1, 0, false).
		AddItem(actionBar, 1, 0, false)

	root.SetBackgroundColor(colBG)
	a.pages.AddPage("dashboard", root, true, true)
}

// ── data refresh ─────────────────────────────────────────────────────────

func (a *App) refreshData() {
	var s statusResp
	if err := apiGet(a.base, "/v1/status", &s); err != nil {
		a.tapp.QueueUpdateDraw(func() {
			if a.statusBar != nil {
				a.statusBar.SetText(fmt.Sprintf(" [%s]⚠ Cannot reach daemon: %s[-]", hex(colRed), err))
			}
		})
		return
	}
	a.status = &s
	a.tapp.QueueUpdateDraw(func() {
		// Recover from any render panic so the TUI stays alive.
		defer func() {
			if r := recover(); r != nil {
				if a.statusBar != nil {
					a.statusBar.SetText(fmt.Sprintf(" [%s]⚠ render error: %v[-]", hex(colRed), r))
				}
			}
		}()
		a.renderSelf(&s)
		a.renderStats(&s)
		a.renderPeers(s.Peers)
		a.statusBar.SetText(fmt.Sprintf(
			" [%s]Last refreshed: %s[-]", hex(colDim), time.Now().Format("15:04:05"),
		))
	})
}

func (a *App) renderSelf(s *statusResp) {
	if a.selfBox == nil {
		return
	}
	role := s.Self.Role
	roleIcon := "📦"
	if role == "leech" {
		roleIcon = "🪱"
	}
	b32 := s.Self.B32
	if len(b32) > 52 {
		b32 = b32[:52]
	}
	a.selfBox.SetText(fmt.Sprintf(
		"\n  [%s]B32:[-]  [%s]%s[-]\n  [%s]Role:[-] %s [%s]%s[-]\n  [%s]Quota:[-][%s]%s[-]\n  [%s]Path:[-] [%s]%s[-]",
		hex(colDim), hex(colText), b32,
		hex(colDim), roleIcon, hex(colText), role,
		hex(colDim), hex(colText), fmtBytes(s.Self.QuotaBytes),
		hex(colDim), hex(colText), s.Self.StoragePath,
	))
}

func (a *App) renderStats(s *statusResp) {
	if a.statsBox == nil {
		return
	}
	a.statsBox.SetText(fmt.Sprintf(
		"\n  [%s]Total peers[-]\n  [%s]%d[-]\n\n  [%s]Storage nodes[-]\n  [%s]%d[-]",
		hex(colDim), hex(colAccent), s.PeerCount,
		hex(colDim), hex(colAccent), s.StoragePeers,
	))
}

func (a *App) renderPeers(peers []peerInfo) {
	if a.peersTable == nil {
		return
	}
	a.peersTable.Clear()
	headers := []string{"  Identity", "Role", "Status", "Quota", "Last Seen", "B32"}
	for col, h := range headers {
		a.peersTable.SetCell(0, col,
			tview.NewTableCell(h).
				SetTextColor(colAccent).
				SetSelectable(false).
				SetExpansion(1))
	}
	for row, p := range peers {
		ident := "  " + p.Phrase[0] + " " + p.Phrase[1] + " " + p.Phrase[2]
		sc, si := statusStyle(p.Status)
		b32 := p.B32
		if len(b32) > 22 {
			b32 = b32[:22] + "…"
		}
		ri := "L"
		if p.Role == "leech" {
			ri = "L"
		}
		ls := "never"
		if !p.LastSeen.IsZero() {
			ls = humanDur(time.Since(p.LastSeen))
		}
		cols := []struct {
			t string
			c tcell.Color
		}{
			{ident, colText},
			{ri + " " + p.Role, colText},
			{si + " " + p.Status, sc},
			{fmtBytes(p.QuotaBytes), colText},
			{ls, colDim},
			{b32, colDim},
		}
		for col, c := range cols {
			a.peersTable.SetCell(row+1, col,
				tview.NewTableCell(c.t).SetTextColor(c.c).SetExpansion(1))
		}
	}
}

// ── Add Node modal ────────────────────────────────────────────────────────

func (a *App) showAddNode() {
	var inv inviteResp
	if err := apiGet(a.base, "/v1/invite", &inv); err != nil {
		a.showMsg("Error", "Failed to generate invite:\n"+err.Error())
		return
	}

	modal := newModal(" ◈ Add Node — share with new machine ")

	b32TV := tview.NewTextView().SetDynamicColors(true).
		SetText(fmt.Sprintf(
			"  [%s]B32 Address[-]\n  [%s]%s[-]",
			hex(colDim), hex(colText), inv.B32,
		))
	b32TV.SetBackgroundColor(colPanel)

	phraseRow := tview.NewFlex().SetDirection(tview.FlexColumn)
	for i, word := range inv.Phrase {
		w := tview.NewTextView().
			SetDynamicColors(true).
			SetTextAlign(tview.AlignCenter).
			SetText(fmt.Sprintf("[%s]%s[-]", hex(colGreen), word))
		w.SetBorder(true).SetBorderColor(colAccent).SetBackgroundColor(colPanel)
		if i > 0 {
			phraseRow.AddItem(bgSpacer(), 2, 0, false)
		}
		phraseRow.AddItem(w, 0, 1, false)
	}

	timerTV := tview.NewTextView().SetDynamicColors(true).SetTextAlign(tview.AlignCenter)
	timerTV.SetBackgroundColor(colPanel)

	doneBtn := tview.NewButton(" Done ").SetSelectedFunc(func() {
		a.pages.RemovePage("addnode")
		a.tapp.SetFocus(a.peersTable)
	})
	doneBtn.SetBackgroundColor(colAccent)
	doneBtn.SetLabelColor(colBG)

	modal.
		AddItem(b32TV, 3, 0, false).
		AddItem(phraseRow, 5, 0, false).
		AddItem(timerTV, 1, 0, false).
		AddItem(bgSpacer(), 1, 0, false).
		AddItem(centreItem(doneBtn, 12), 1, 0, true)

	deadline := time.Now().Add(10 * time.Minute)
	go func() {
		for {
			rem := time.Until(deadline)
			if rem <= 0 {
				a.tapp.QueueUpdateDraw(func() {
					timerTV.SetText(fmt.Sprintf("  [%s]⏱ Expired — generate a new invite[-]", hex(colRed)))
				})
				return
			}
			m, s := int(rem.Minutes()), int(rem.Seconds())%60
			a.tapp.QueueUpdateDraw(func() {
				timerTV.SetText(fmt.Sprintf("  [%s]⏱ Expires in %02d:%02d[-]", hex(colYellow), m, s))
			})
			time.Sleep(time.Second)
		}
	}()

	a.pages.AddPage("addnode", centreModal(modal, 70, 18), true, true)
	a.tapp.SetFocus(doneBtn)
}

// ── Join Cloud modal ──────────────────────────────────────────────────────

func (a *App) showJoinCloud() {
	modal := newModal(" ◈ Join JunkNAS Cloud ")

	b32In := styledField("Paste existing node B32 address")
	w1 := styledField("Word 1")
	w2 := styledField("Word 2")
	w3 := styledField("Word 3")

	phraseRow := tview.NewFlex().SetDirection(tview.FlexColumn).
		AddItem(w1, 0, 1, false).
		AddItem(bgSpacer(), 2, 0, false).
		AddItem(w2, 0, 1, false).
		AddItem(bgSpacer(), 2, 0, false).
		AddItem(w3, 0, 1, false)

	storeCheck := tview.NewCheckbox().
		SetLabel("  Store files on this device").
		SetChecked(true).
		SetFieldBackgroundColor(colBG).
		SetLabelColor(colText)

	quotaIn := styledField("Storage quota in GB  (e.g. 200)")

	// errTV must be *tview.TextView, not *tview.Box
	errTV := tview.NewTextView().SetDynamicColors(true)
	errTV.SetBackgroundColor(colPanel)

	cancelBtn := tview.NewButton(" Cancel ").SetSelectedFunc(func() {
		a.pages.RemovePage("joincloud")
		a.tapp.SetFocus(a.peersTable)
	})
	cancelBtn.SetBackgroundColor(colDim)
	cancelBtn.SetLabelColor(colBG)

	joinBtn := tview.NewButton("  Join  ").SetSelectedFunc(func() {
		b32 := strings.TrimSpace(b32In.GetText())
		p1 := strings.TrimSpace(w1.GetText())
		p2 := strings.TrimSpace(w2.GetText())
		p3 := strings.TrimSpace(w3.GetText())
		if b32 == "" || p1 == "" || p2 == "" || p3 == "" {
			errTV.SetText(fmt.Sprintf("[%s]⚠ All fields are required.[-]", hex(colRed)))
			return
		}
		qgb, _ := strconv.ParseInt(strings.TrimSpace(quotaIn.GetText()), 10, 64)
		if qgb <= 0 {
			qgb = 100
		}
		role := "leech"
		if storeCheck.IsChecked() {
			role = "storage"
		}
		payload := map[string]any{
			"target_b32":  b32,
			"phrase":      [3]string{p1, p2, p3},
			"role":        role,
			"quota_bytes": qgb * (1 << 30),
		}
		var result map[string]string
		if err := apiPost(a.base, "/v1/connect", payload, &result); err != nil {
			errTV.SetText(fmt.Sprintf("[%s]⚠ Join failed: %s[-]", hex(colRed), err))
			return
		}
		a.pages.RemovePage("joincloud")
		a.refreshData()
	})
	joinBtn.SetBackgroundColor(colAccent)
	joinBtn.SetLabelColor(colBG)

	btnRow := tview.NewFlex().SetDirection(tview.FlexColumn).
		AddItem(cancelBtn, 10, 0, false).
		AddItem(bgSpacer(), 0, 1, false).
		AddItem(joinBtn, 10, 0, false)
	btnRow.SetBackgroundColor(colPanel)

	lbl := func(t string) *tview.TextView {
		v := tview.NewTextView().SetDynamicColors(true).
			SetText(fmt.Sprintf("[%s]%s[-]", hex(colDim), t))
		v.SetBackgroundColor(colPanel)
		return v
	}

	modal.
		AddItem(lbl("B32 Address of an existing node:"), 1, 0, false).
		AddItem(b32In, 1, 0, true).
		AddItem(bgSpacer(), 1, 0, false).
		AddItem(lbl("Passphrase (3 separate words):"), 1, 0, false).
		AddItem(phraseRow, 1, 0, false).
		AddItem(bgSpacer(), 1, 0, false).
		AddItem(storeCheck, 1, 0, false).
		AddItem(quotaIn, 1, 0, false).
		AddItem(bgSpacer(), 1, 0, false).
		AddItem(errTV, 1, 0, false).
		AddItem(btnRow, 1, 0, false)

	a.pages.AddPage("joincloud", centreModal(modal, 72, 22), true, true)
	a.tapp.SetFocus(b32In)
}

// ── utility modal ─────────────────────────────────────────────────────────

func (a *App) showMsg(title, msg string) {
	m := tview.NewModal().
		SetText(msg).
		AddButtons([]string{"OK"}).
		SetDoneFunc(func(_ int, _ string) { a.pages.RemovePage("msg") })
	m.SetBackgroundColor(colPanel).SetTextColor(colText)
	a.pages.AddPage("msg", m, true, true)
}

// ── helper widgets ────────────────────────────────────────────────────────

func newModal(title string) *tview.Flex {
	f := tview.NewFlex().SetDirection(tview.FlexRow)
	f.SetBorder(true).
		SetTitle(title).
		SetTitleColor(colAccent).
		SetBorderColor(colAccent).
		SetBackgroundColor(colPanel)
	return f
}

func centreModal(p tview.Primitive, w, h int) tview.Primitive {
	return tview.NewFlex().
		AddItem(nil, 0, 1, false).
		AddItem(tview.NewFlex().SetDirection(tview.FlexRow).
			AddItem(nil, 0, 1, false).
			AddItem(p, h, 0, true).
			AddItem(nil, 0, 1, false), w, 0, true).
		AddItem(nil, 0, 1, false)
}

// bgSpacer is a transparent spacer that inherits panel background.
func bgSpacer() *tview.TextView {
	t := tview.NewTextView()
	t.SetBackgroundColor(colPanel)
	return t
}

func centreItem(p tview.Primitive, width int) *tview.Flex {
	return tview.NewFlex().SetDirection(tview.FlexColumn).
		AddItem(nil, 0, 1, false).
		AddItem(p, width, 0, true).
		AddItem(nil, 0, 1, false)
}

func styledField(placeholder string) *tview.InputField {
	return tview.NewInputField().
		SetPlaceholder(placeholder).
		SetPlaceholderTextColor(colDim).
		SetFieldBackgroundColor(colBG).
		SetFieldTextColor(colText).
		SetLabelColor(colDim)
}

func statusStyle(s string) (tcell.Color, string) {
	switch s {
	case "healthy":
		return colGreen, "●"
	case "degraded":
		return colYellow, "◐"
	case "unreachable":
		return colRed, "○"
	default:
		return colDim, "◌"
	}
}

func hex(c tcell.Color) string {
	r, g, b := c.RGB()
	return fmt.Sprintf("#%02x%02x%02x", r, g, b)
}

func fmtBytes(n int64) string {
	switch {
	case n >= 1<<40:
		return fmt.Sprintf("%.1f TiB", float64(n)/(1<<40))
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GiB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20))
	default:
		return fmt.Sprintf("%d B", n)
	}
}

func humanDur(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	}
}
