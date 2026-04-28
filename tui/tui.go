package tui

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/junknas/junknas/internal/join"
	"github.com/junknas/junknas/internal/daemon"
	"github.com/rivo/tview"
	"github.com/f1bonacc1/glippy"

)

// Colour palette
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

var httpClient = &http.Client{Timeout: 5 * time.Second}

func copyToClipboard(text string) error {
	if err := glippy.Set(text); err == nil {
		return nil
	}
	return fmt.Errorf("Clipboard error")
}

type DiskInfo struct {
	MountPoint string
	Device     string
	FreeBytes  int64
	TotalBytes int64
}

func discoverDisks() []DiskInfo {
	var disks []DiskInfo
	f, err := os.Open("/proc/mounts")
	if err != nil {
		return disks
	}
	defer f.Close()

	skip := map[string]bool{
		"sysfs": true, "proc": true, "devtmpfs": true, "devpts": true,
		"tmpfs": true, "cgroup": true, "cgroup2": true, "pstore": true,
		"bpf": true, "tracefs": true, "debugfs": true, "securityfs": true,
		"fusectl": true, "hugetlbfs": true, "mqueue": true, "configfs": true,
		"efivarfs": true, "squashfs": true, "overlay": true, "aufs": true,
	}
	seen := map[string]bool{}

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 3 {
			continue
		}
		device, mountPoint, fsType := fields[0], fields[1], fields[2]
		if skip[fsType] {
			continue
		}
		if seen[mountPoint] {
			continue
		}
		if strings.HasPrefix(device, "none") || strings.HasPrefix(mountPoint, "/sys") ||
			strings.HasPrefix(mountPoint, "/proc") || strings.HasPrefix(mountPoint, "/dev") ||
			strings.HasPrefix(mountPoint, "/run") {
			continue
		}

		var st syscall.Statfs_t
		if err := syscall.Statfs(mountPoint, &st); err != nil {
			continue
		}
		free := int64(st.Bavail) * int64(st.Bsize)
		total := int64(st.Blocks) * int64(st.Bsize)
		if free < 1<<30 {
			continue
		}
		seen[mountPoint] = true
		disks = append(disks, DiskInfo{
			MountPoint: mountPoint,
			Device:     device,
			FreeBytes:  free,
			TotalBytes: total,
		})
	}
	return disks
}

func apiBase() (string, error) {
	lockPath := "/tmp/junknas.lock"
	if _, err := os.Stat(lockPath); os.IsNotExist(err) {
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
	resp, err := httpClient.Get(base + path)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return json.NewDecoder(resp.Body).Decode(out)
}

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

type App struct {
	tapp   *tview.Application
	pages  *tview.Pages
	base   string
	status *statusResp
	daemon	*daemon.Daemon

	selfBox    *tview.TextView
	statsBox   *tview.TextView
	peersTable *tview.Table
	statusBar  *tview.TextView
}

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
			go a.refreshData()
		case 'q', 'Q':
			a.tapp.Stop()
		}
		return ev
	})

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

func (a *App) buildDashboard() {
	header := tview.NewTextView().SetDynamicColors(true).SetText(
		fmt.Sprintf("[%s]## JunkNAS[-]  [%s]Distributed Private Cloud · I2P · SMB3[-]",
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

func (a *App) refreshData() {
	var s statusResp
	if err := apiGet(a.base, "/v1/status", &s); err != nil {
		a.tapp.QueueUpdateDraw(func() {
			if a.statusBar != nil {
				a.statusBar.SetText(fmt.Sprintf(" [%s]! Cannot reach daemon: %s[-]", hex(colRed), err))
			}
		})
		return
	}
	a.status = &s
	a.tapp.QueueUpdateDraw(func() {
		defer func() {
			if r := recover(); r != nil {
				if a.statusBar != nil {
					a.statusBar.SetText(fmt.Sprintf(" [%s]! render error: %v[-]", hex(colRed), r))
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
	roleIcon := "[S]"
	if role == "leech" {
		roleIcon = "[L]"
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
			b32 = b32[:22] + "~"
		}
		ri := "[S]"
		if p.Role == "leech" {
			ri = "[L]"
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

func (a *App) showAddNode() {
	var inv inviteResp
	if err := apiGet(a.base, "/v1/invite", &inv); err != nil {
		a.showMsg("Error", "Failed to generate invite:\n"+err.Error())
		return
	}

	modal := newModal(" [+] Add Node — share with new machine ")

	b32 := inv.B32

	b32Display := tview.NewTextView().SetDynamicColors(true).
		SetText(fmt.Sprintf(
			"  [%s]B32 Address[-]\n  [%s]%s[-]",
			hex(colDim), hex(colAccent), b32,
		))
	b32Display.SetBackgroundColor(colPanel)

	copyStatus := tview.NewTextView().SetDynamicColors(true).SetTextAlign(tview.AlignCenter)
	copyStatus.SetBackgroundColor(colPanel)
	
	copyBtn := tview.NewButton("  [C] Copy B32 to clipboard  ").
		SetSelectedFunc(func() {
			copyToClipboard(fmt.Sprintf(b32))
		})
	copyBtn.SetBackgroundColor(colPanel)
	copyBtn.SetLabelColor(colAccent)

	b32Container := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(b32Display, 3, 0, false).
		AddItem(copyBtn, 1, 0, true).
		AddItem(copyStatus, 1, 0, false)
	b32Container.SetBackgroundColor(colPanel)

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
		AddItem(b32Container, 5, 0, false).
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
					timerTV.SetText(fmt.Sprintf("  [%s]Timer: Expired — generate a new invite[-]", hex(colRed)))
				})
				return
			}
			m, s := int(rem.Minutes()), int(rem.Seconds())%60
			a.tapp.QueueUpdateDraw(func() {
				timerTV.SetText(fmt.Sprintf("  [%s]Expires in %02d:%02d[-]", hex(colYellow), m, s))
			})
			time.Sleep(time.Second)
		}
	}()

	a.pages.AddPage("addnode", centreModal(modal, 72, 20), true, true)
	a.tapp.SetFocus(doneBtn)
}

type diskQuotaEntry struct {
	disk       DiskInfo
	quotaGiB   int64
	inputField *tview.InputField
}

func (a *App) showJoinCloud() {
	disks := discoverDisks()

	modal := newModal(" [>] Join JunkNAS Cloud ")

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

	// ── Storage mode checkbox — OFF by default (leech is default) ─────────
	storeCheck := tview.NewCheckbox().
		SetLabel("  Enable storage mode (contribute disk space)").
		SetChecked(false). // leech by default
		SetFieldBackgroundColor(colBG).
		SetLabelColor(colText)

	errTV := tview.NewTextView().SetDynamicColors(true)
	errTV.SetBackgroundColor(colPanel)

	lbl := func(t string) *tview.TextView {
		v := tview.NewTextView().SetDynamicColors(true).
			SetText(fmt.Sprintf("[%s]%s[-]", hex(colDim), t))
		v.SetBackgroundColor(colPanel)
		return v
	}

	diskEntries := []diskQuotaEntry{}
	diskFlex := tview.NewFlex().SetDirection(tview.FlexRow)
	diskFlex.SetBackgroundColor(colPanel)

	diskHeader := tview.NewTextView().SetDynamicColors(true).SetText(
		fmt.Sprintf("[%s]%-24s  %-12s  %-12s  %s[-]",
			hex(colAccent), "Mount Point", "Free", "Total", "Quota (GiB)"))
	diskHeader.SetBackgroundColor(colPanel)

	if len(disks) == 0 {
		noDisks := tview.NewTextView().SetDynamicColors(true).SetText(
			fmt.Sprintf("[%s]No suitable disks found (need >= 1 GiB free)[-]", hex(colYellow)))
		noDisks.SetBackgroundColor(colPanel)
		diskFlex.AddItem(noDisks, 1, 0, false)
	} else {
		diskFlex.AddItem(diskHeader, 1, 0, false)
		for _, d := range disks {
			entry := diskQuotaEntry{
				disk:     d,
				quotaGiB: d.FreeBytes >> 30,
			}
			row := tview.NewFlex().SetDirection(tview.FlexColumn)
			row.SetBackgroundColor(colPanel)

			diskLabel := tview.NewTextView().SetDynamicColors(true).SetText(
				fmt.Sprintf("[%s]%-24s  %-12s  %-12s[-]",
					hex(colText),
					truncStr(d.MountPoint, 24),
					fmtBytes(d.FreeBytes),
					fmtBytes(d.TotalBytes),
				))
			diskLabel.SetBackgroundColor(colPanel)

			defaultVal := strconv.FormatInt(entry.quotaGiB, 10)
			qField := tview.NewInputField().
				SetText(defaultVal).
				SetFieldWidth(8).
				SetFieldBackgroundColor(colPanel). // greyed out initially
				SetFieldTextColor(colDim).         // greyed out initially
				SetLabelColor(colDim).
				SetAcceptanceFunc(tview.InputFieldInteger)

			entry.inputField = qField
			diskEntries = append(diskEntries, entry)

			row.AddItem(diskLabel, 0, 1, false)
			row.AddItem(qField, 10, 0, false) // not focusable until enabled
			diskFlex.AddItem(row, 1, 0, false)
		}
	}

	diskBox := tview.NewFlex().SetDirection(tview.FlexRow)
	diskBox.SetBorder(true).
		SetTitle(" Per-Disk Quota Allocation (storage mode disabled) ").
		SetTitleColor(colDim).
		SetBorderColor(colDim). // greyed out initially
		SetBackgroundColor(colPanel)
	diskBox.AddItem(diskFlex, 0, 1, false)

	diskBoxHeight := 2 + len(diskEntries)
	if diskBoxHeight > 15 {
		diskBoxHeight = 15
	}
	totalHeight := 22 + diskBoxHeight

	// setDiskFieldsEnabled toggles the visual and interactive state of each
	// quota input field based on whether storage mode is active.
	setDiskFieldsEnabled := func(enabled bool) {
		for i := range diskEntries {
			if enabled {
				diskEntries[i].inputField.
					SetFieldBackgroundColor(colBG).
					SetFieldTextColor(colText)
			} else {
				diskEntries[i].inputField.
					SetFieldBackgroundColor(colPanel).
					SetFieldTextColor(colDim)
			}
		}
	}

	updateDiskVisibility := func(checked bool) {
		if checked {
			diskBox.SetBorderColor(colAccent)
			diskBox.SetTitleColor(colAccent)
			diskBox.SetTitle(" Per-Disk Quota Allocation (GiB — edit to adjust) ")
			setDiskFieldsEnabled(true)
		} else {
			diskBox.SetBorderColor(colDim)
			diskBox.SetTitleColor(colDim)
			diskBox.SetTitle(" Per-Disk Quota Allocation (storage mode disabled) ")
			setDiskFieldsEnabled(false)
		}
	}

	storeCheck.SetChangedFunc(func(checked bool) {
		updateDiskVisibility(checked)
		if checked && len(diskEntries) > 0 {
			a.tapp.SetFocus(diskEntries[0].inputField)
		}
	})
	// Apply initial greyed-out state (storage mode is off by default).
	updateDiskVisibility(false)

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
			a.tapp.QueueUpdateDraw(func() {
				errTV.SetText(fmt.Sprintf("[%s]All fields are required.[-]", hex(colRed)))
			})
			return
		}

		var totalQuotaBytes int64
		storagePath := ""

		if storeCheck.IsChecked() {
			if len(diskEntries) > 0 {
				var maxQuota int64
				for i := range diskEntries {
					qgb, _ := strconv.ParseInt(strings.TrimSpace(diskEntries[i].inputField.GetText()), 10, 64)
					if qgb < 0 {
						qgb = 0
					}
					maxFree := diskEntries[i].disk.FreeBytes >> 30
					if qgb > maxFree {
						qgb = maxFree
					}
					diskEntries[i].quotaGiB = qgb
					totalQuotaBytes += qgb << 30
					if qgb > maxQuota {
						maxQuota = qgb
						storagePath = diskEntries[i].disk.MountPoint + ".junknas"
					}
				}
				if totalQuotaBytes == 0 {
					a.tapp.QueueUpdateDraw(func() {
						errTV.SetText(fmt.Sprintf("[%s]Quota must be > 0 GiB on at least one disk.[-]", hex(colRed)))
					})
					return
				}
			} else {
				// Storage mode checked but no disks discovered — block join.
				a.tapp.QueueUpdateDraw(func() {
					errTV.SetText(fmt.Sprintf("[%s]No suitable disks found. Uncheck storage mode to join as leech.[-]", hex(colRed)))
				})
				return
			}
		}
		// If storage mode is off, totalQuotaBytes stays 0 and role is leech.

		role := "leech"
		if storeCheck.IsChecked() {
			role = "storage"
		}

		payload := map[string]any{
			"target_b32":  b32,
			"phrase":      [3]string{p1, p2, p3},
			"role":        role,
			"quota_bytes": totalQuotaBytes,
		}
		if storagePath != "" {
			payload["storage_path"] = storagePath
		}

		a.pages.RemovePage("joincloud")
		a.showJoinProgress(b32, payload)
	})
	joinBtn.SetBackgroundColor(colAccent)
	joinBtn.SetLabelColor(colBG)

	btnRow := tview.NewFlex().SetDirection(tview.FlexColumn).
		AddItem(cancelBtn, 10, 0, false).
		AddItem(bgSpacer(), 0, 1, false).
		AddItem(joinBtn, 10, 0, false)
	btnRow.SetBackgroundColor(colPanel)

	modal.
		AddItem(lbl("B32 Address of an existing node:"), 1, 0, false).
		AddItem(b32In, 1, 0, true).
		AddItem(bgSpacer(), 1, 0, false).
		AddItem(lbl("Passphrase (3 separate words):"), 1, 0, false).
		AddItem(phraseRow, 1, 0, false).
		AddItem(bgSpacer(), 1, 0, false).
		AddItem(storeCheck, 1, 0, false).
		AddItem(bgSpacer(), 1, 0, false).
		AddItem(diskBox, diskBoxHeight, 0, false). // not focusable until storage enabled
		AddItem(bgSpacer(), 1, 0, false).
		AddItem(errTV, 1, 0, false).
		AddItem(btnRow, 1, 0, false)

	a.pages.AddPage("joincloud", centreModal(modal, 78, totalHeight), true, true)
	a.tapp.SetFocus(b32In)
}

func (a *App) showJoinProgress(targetB32 string, payload map[string]any) {
	modal := newModal(" [>] Joining JunkNAS Cloud — connecting... ")

	logView := tview.NewTextView().
		SetDynamicColors(true).
		SetScrollable(true).
		SetWrap(true)
	logView.SetBackgroundColor(colPanel)

	statusLine := tview.NewTextView().SetDynamicColors(true)
	statusLine.SetBackgroundColor(colPanel)

	closeBtn := tview.NewButton(" Close ").SetSelectedFunc(func() {
		a.pages.RemovePage("joinprogress")
		a.tapp.SetFocus(a.peersTable)
		go a.refreshData()
	})
	closeBtn.SetBackgroundColor(colDim)
	closeBtn.SetLabelColor(colBG)
	closeBtn.SetDisabled(true)

	modal.
		AddItem(logView, 0, 1, false).
		AddItem(statusLine, 1, 0, false).
		AddItem(bgSpacer(), 1, 0, false).
		AddItem(centreItem(closeBtn, 12), 1, 0, true)

	a.pages.AddPage("joinprogress", centreModal(modal, 78, 26), true, true)
	a.tapp.SetFocus(logView)

	appendLog := func(color tcell.Color, format string, args ...any) {
		msg := fmt.Sprintf(format, args...)
		ts := time.Now().Format("15:04:05")
		line := fmt.Sprintf("[%s]%s[-]  [%s]%s[-]\n", hex(colDim), ts, hex(color), msg)
		a.tapp.QueueUpdateDraw(func() {
			fmt.Fprint(logView, line)
			logView.ScrollToEnd()
		})
	}
	setStatus := func(color tcell.Color, msg string) {
		a.tapp.QueueUpdateDraw(func() {
			statusLine.SetText(fmt.Sprintf(" [%s]%s[-]", hex(color), msg))
		})
	}
	enableClose := func() {
		a.tapp.QueueUpdateDraw(func() {
			closeBtn.SetDisabled(false)
			closeBtn.SetBackgroundColor(colAccent)
			closeBtn.SetLabelColor(colBG)
			a.tapp.SetFocus(closeBtn)
		})
	}

	go func() {
		appendLog(colText, "Preparing join request...")
		appendLog(colDim, "Target: %s", truncStr(targetB32, 52))
		role, _ := payload["role"].(string)
		appendLog(colDim, "Role: %s", role)
		if qb, ok := payload["quota_bytes"].(int64); ok && qb > 0 {
			appendLog(colDim, "Quota: %s", fmtBytes(qb))
		}
		appendLog(colText, "Sending join request over I2P...")
		appendLog(colYellow, "This may take 30-120 seconds while I2P tunnels establish...")
		setStatus(colYellow, "Waiting for response from target node...")

		body, _ := json.Marshal(payload)
		req, err := http.NewRequest("POST", a.base+"/v1/connect", strings.NewReader(string(body)))
		if err != nil {
			appendLog(colRed, "Failed to create request: %v", err)
			setStatus(colRed, "Join failed")
			enableClose()
			return
		}
		req.Header.Set("Content-Type", "application/json")

		client := a.daemon.Proto.HttpClient
		resp, err := client.Do(req)
		if err != nil {
			appendLog(colRed, "Connection failed: %v", err)
			setStatus(colRed, "Join failed — check that the target node is reachable and I2P is running")
			enableClose()
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			appendLog(colRed, "Join rejected: %s", resp.Status)
			if len(body) > 0 {
				appendLog(colRed, "Error: %s", string(body))
			}
			setStatus(colRed, "Join rejected")
			enableClose()
			return
		}

		var jr join.JoinResponse
		if err := json.NewDecoder(resp.Body).Decode(&jr); err != nil {
			appendLog(colRed, "Invalid response: %v", err)
			setStatus(colRed, "Join failed: malformed response")
			enableClose()
			return
		}

		appendLog(colGreen, "Join successful! Received %d peers.", len(jr.Peers))
		setStatus(colGreen, "Join successful – cloud ready")
		go a.refreshData()
		enableClose()
	}()
}

func (a *App) showMsg(title, msg string) {
	m := tview.NewModal().
		SetText(msg).
		AddButtons([]string{"OK"}).
		SetDoneFunc(func(_ int, _ string) { a.pages.RemovePage("msg") })
	m.SetBackgroundColor(colPanel).SetTextColor(colText)
	a.pages.AddPage("msg", m, true, true)
}

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
		return colGreen, "(+)"
	case "degraded":
		return colYellow, "(~)"
	case "unreachable":
		return colRed, "(!)"
	default:
		return colDim, "(?)"
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

func truncStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "~"
}
