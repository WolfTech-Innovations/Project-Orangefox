package main

import (
	"bytes"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/rivo/tview"
)

//go:embed embedded/*
var embeddedFS embed.FS

type ProcessInfo struct {
	Name    string
	Cmd     *exec.Cmd
	Status  string
	Output  []string
	mu      sync.Mutex
}

type Member struct {
	Address   string    `json:"address"`
	Name      string    `json:"name"`
	Mnemonic  string    `json:"mnemonic"`
	JoinDate  time.Time `json:"join_date"`
	Balance   string    `json:"balance"`
	LastUBI   time.Time `json:"last_ubi"`
	IsVendor  bool      `json:"is_vendor"`
	VendorKey string    `json:"vendor_key,omitempty"`
}

type Vendor struct {
	Address     string    `json:"address"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Items       []Item    `json:"items"`
	APIKey      string    `json:"api_key"`
	Active      bool      `json:"active"`
	JoinDate    time.Time `json:"join_date"`
}

type Item struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Price       string `json:"price"`
	Stock       int    `json:"stock"`
	Available   bool   `json:"available"`
}

type Purchase struct {
	ID        string    `json:"id"`
	Buyer     string    `json:"buyer"`
	Vendor    string    `json:"vendor"`
	ItemID    string    `json:"item_id"`
	Amount    string    `json:"amount"`
	Timestamp time.Time `json:"timestamp"`
	Status    string    `json:"status"`
}

type Transaction struct {
	From      string    `json:"from"`
	To        string    `json:"to"`
	Amount    string    `json:"amount"`
	Timestamp time.Time `json:"timestamp"`
	Type      string    `json:"type"`
}

type CommunityState struct {
	Members      map[string]*Member `json:"members"`
	Vendors      map[string]*Vendor `json:"vendors"`
	Purchases    []Purchase         `json:"purchases"`
	Transactions []Transaction      `json:"transactions"`
	UBIAmount    string            `json:"ubi_amount"`
	UBIInterval  time.Duration     `json:"ubi_interval"`
	LastUBI      time.Time         `json:"last_ubi"`
	mu           sync.RWMutex
}

type WalletResponse struct {
	Address    string `json:"address"`
	PrivateKey string `json:"privateKey"`
	Mnemonic   string `json:"mnemonic"`
}

type BalanceResponse struct {
	Balance string `json:"balance"`
}

var (
	state         *CommunityState
	wolfEtherURL  = "http://localhost:8545"
	processes     []*ProcessInfo
	app           *tview.Application
	pages         *tview.Pages
)

func (p *ProcessInfo) AddOutput(line string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.Output = append(p.Output, line)
	if len(p.Output) > 1000 {
		p.Output = p.Output[len(p.Output)-1000:]
	}
}

func (p *ProcessInfo) GetOutput() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string{}, p.Output...)
}

func initCommunityState() {
	state = &CommunityState{
		Members:      make(map[string]*Member),
		Vendors:      make(map[string]*Vendor),
		Purchases:    []Purchase{},
		Transactions: []Transaction{},
		UBIAmount:    "100",
		UBIInterval:  24 * time.Hour,
		LastUBI:      time.Now(),
	}
	loadState()
}

func loadState() {
	data, err := os.ReadFile("community_state.json")
	if err != nil {
		return
	}
	json.Unmarshal(data, state)
}

func saveState() {
	state.mu.RLock()
	defer state.mu.RUnlock()
	data, _ := json.MarshalIndent(state, "", "  ")
	os.WriteFile("community_state.json", data, 0644)
}

func generateAPIKey() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func verifyVendorKey(address, apiKey string) bool {
	state.mu.RLock()
	defer state.mu.RUnlock()
	
	vendor, exists := state.Vendors[address]
	if !exists || !vendor.Active {
		return false
	}
	return vendor.APIKey == apiKey
}

func createPurchase(buyer, vendor, itemID, amount string) (*Purchase, error) {
	state.mu.Lock()
	defer state.mu.Unlock()
	
	v, exists := state.Vendors[vendor]
	if !exists {
		return nil, fmt.Errorf("vendor not found")
	}
	
	var item *Item
	for i := range v.Items {
		if v.Items[i].ID == itemID {
			item = &v.Items[i]
			break
		}
	}
	
	if item == nil || !item.Available || item.Stock <= 0 {
		return nil, fmt.Errorf("item not available")
	}
	
	purchase := Purchase{
		ID:        generateAPIKey()[:16],
		Buyer:     buyer,
		Vendor:    vendor,
		ItemID:    itemID,
		Amount:    amount,
		Timestamp: time.Now(),
		Status:    "completed",
	}
	
	item.Stock--
	if item.Stock == 0 {
		item.Available = false
	}
	
	state.Purchases = append(state.Purchases, purchase)
	state.Transactions = append(state.Transactions, Transaction{
		From:      buyer,
		To:        vendor,
		Amount:    amount,
		Timestamp: time.Now(),
		Type:      "purchase",
	})
	
	saveState()
	return &purchase, nil
}

// Marketplace API Server
func startMarketplaceAPI() {
	mux := http.NewServeMux()
	
	// Middleware for API key verification
	requireVendorAuth := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			apiKey := r.Header.Get("X-API-Key")
			vendorAddr := r.Header.Get("X-Vendor-Address")
			
			if apiKey == "" || vendorAddr == "" {
				http.Error(w, "Missing authentication headers", http.StatusUnauthorized)
				return
			}
			
			if !verifyVendorKey(vendorAddr, apiKey) {
				http.Error(w, "Invalid API key", http.StatusForbidden)
				return
			}
			
			next(w, r)
		}
	}
	
	// GET /api/vendors - List all vendors (public)
	mux.HandleFunc("/api/vendors", func(w http.ResponseWriter, r *http.Request) {
		state.mu.RLock()
		defer state.mu.RUnlock()
		
		vendors := []map[string]interface{}{}
		for _, v := range state.Vendors {
			if v.Active {
				vendors = append(vendors, map[string]interface{}{
					"address":     v.Address,
					"name":        v.Name,
					"description": v.Description,
					"items":       len(v.Items),
					"join_date":   v.JoinDate,
				})
			}
		}
		
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"vendors": vendors,
			"count":   len(vendors),
		})
	})
	
	// GET /api/items - List all available items (public)
	mux.HandleFunc("/api/items", func(w http.ResponseWriter, r *http.Request) {
		state.mu.RLock()
		defer state.mu.RUnlock()
		
		items := []map[string]interface{}{}
		for _, vendor := range state.Vendors {
			if !vendor.Active {
				continue
			}
			for _, item := range vendor.Items {
				if item.Available && item.Stock > 0 {
					items = append(items, map[string]interface{}{
						"id":          item.ID,
						"name":        item.Name,
						"description": item.Description,
						"price":       item.Price,
						"stock":       item.Stock,
						"vendor":      vendor.Name,
						"vendor_addr": vendor.Address,
					})
				}
			}
		}
		
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"items": items,
			"count": len(items),
		})
	})
	
	// POST /api/vendor/items - Add item (requires vendor auth)
	mux.HandleFunc("/api/vendor/items", requireVendorAuth(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		
		vendorAddr := r.Header.Get("X-Vendor-Address")
		
		var req struct {
			Name        string `json:"name"`
			Description string `json:"description"`
			Price       string `json:"price"`
			Stock       int    `json:"stock"`
		}
		
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}
		
		state.mu.Lock()
		vendor := state.Vendors[vendorAddr]
		
		item := Item{
			ID:          generateAPIKey()[:12],
			Name:        req.Name,
			Description: req.Description,
			Price:       req.Price,
			Stock:       req.Stock,
			Available:   true,
		}
		
		vendor.Items = append(vendor.Items, item)
		state.mu.Unlock()
		saveState()
		
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"item":    item,
		})
	}))
	
	// PUT /api/vendor/items/:id - Update item (requires vendor auth)
	mux.HandleFunc("/api/vendor/items/", requireVendorAuth(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "PUT" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		
		vendorAddr := r.Header.Get("X-Vendor-Address")
		itemID := strings.TrimPrefix(r.URL.Path, "/api/vendor/items/")
		
		var req struct {
			Price     *string `json:"price,omitempty"`
			Stock     *int    `json:"stock,omitempty"`
			Available *bool   `json:"available,omitempty"`
		}
		
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}
		
		state.mu.Lock()
		vendor := state.Vendors[vendorAddr]
		
		var updated bool
		for i := range vendor.Items {
			if vendor.Items[i].ID == itemID {
				if req.Price != nil {
					vendor.Items[i].Price = *req.Price
				}
				if req.Stock != nil {
					vendor.Items[i].Stock = *req.Stock
				}
				if req.Available != nil {
					vendor.Items[i].Available = *req.Available
				}
				updated = true
				break
			}
		}
		state.mu.Unlock()
		
		if !updated {
			http.Error(w, "Item not found", http.StatusNotFound)
			return
		}
		
		saveState()
		
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
		})
	}))
	
	// GET /api/vendor/sales - Get vendor sales (requires vendor auth)
	mux.HandleFunc("/api/vendor/sales", requireVendorAuth(func(w http.ResponseWriter, r *http.Request) {
		vendorAddr := r.Header.Get("X-Vendor-Address")
		
		state.mu.RLock()
		defer state.mu.RUnlock()
		
		sales := []Purchase{}
		for _, purchase := range state.Purchases {
			if purchase.Vendor == vendorAddr {
				sales = append(sales, purchase)
			}
		}
		
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"sales": sales,
			"count": len(sales),
		})
	}))
	
	// POST /api/purchase - Make a purchase (public, but requires wallet signature in production)
	mux.HandleFunc("/api/purchase", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		
		var req struct {
			Buyer  string `json:"buyer"`
			Vendor string `json:"vendor"`
			ItemID string `json:"item_id"`
		}
		
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}
		
		// Get item price
		state.mu.RLock()
		vendor, exists := state.Vendors[req.Vendor]
		if !exists {
			state.mu.RUnlock()
			http.Error(w, "Vendor not found", http.StatusNotFound)
			return
		}
		
		var price string
		for _, item := range vendor.Items {
			if item.ID == req.ItemID {
				price = item.Price
				break
			}
		}
		state.mu.RUnlock()
		
		if price == "" {
			http.Error(w, "Item not found", http.StatusNotFound)
			return
		}
		
		purchase, err := createPurchase(req.Buyer, req.Vendor, req.ItemID, price)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success":  true,
			"purchase": purchase,
		})
	})
	
	// Health check
	mux.HandleFunc("/api/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "ok",
			"time":   time.Now(),
		})
	})
	
	http.ListenAndServe(":8547", mux)
}

func getBalance(address string) (string, error) {
	resp, err := http.Get(fmt.Sprintf("%s/balance?address=%s", wolfEtherURL, address))
	if err != nil {
		return "0", err
	}
	defer resp.Body.Close()
	
	var balResp BalanceResponse
	if err := json.NewDecoder(resp.Body).Decode(&balResp); err != nil {
		return "0", err
	}
	return balResp.Balance, nil
}

func createWallet() (*WalletResponse, error) {
	resp, err := http.Get(fmt.Sprintf("%s/wallet", wolfEtherURL))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	
	var wallet WalletResponse
	if err := json.NewDecoder(resp.Body).Decode(&wallet); err != nil {
		return nil, err
	}
	return &wallet, nil
}

func sendTransaction(from, to, amount, privKey string) error {
	data := map[string]string{
		"from":    from,
		"to":      to,
		"amount":  amount,
		"privKey": privKey,
	}
	jsonData, _ := json.Marshal(data)
	
	resp, err := http.Post(fmt.Sprintf("%s/send", wolfEtherURL), "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

func distributeUBI() {
	state.mu.Lock()
	defer state.mu.Unlock()
	
	if time.Since(state.LastUBI) < state.UBIInterval {
		return
	}
	
	for addr, member := range state.Members {
		// In production, you'd need to store private keys securely
		// This is simplified for demonstration
		state.Transactions = append(state.Transactions, Transaction{
			From:      "system",
			To:        addr,
			Amount:    state.UBIAmount,
			Timestamp: time.Now(),
			Type:      "UBI",
		})
		member.LastUBI = time.Now()
	}
	
	state.LastUBI = time.Now()
	saveState()
}

func startProcessMonitor(idx int, tmpDir string, updateUI func()) {
	proc := processes[idx]
	binPath := filepath.Join(tmpDir, proc.Name)
	
	var cmd *exec.Cmd
	if proc.Name == "atr-net" {
		cmd = exec.Command(binPath)
		stdin, err := cmd.StdinPipe()
		if err == nil {
			go func() {
				time.Sleep(100 * time.Millisecond)
				stdin.Write([]byte("Y\n"))
				stdin.Close()
			}()
		}
	} else {
		cmd = exec.Command(binPath)
	}
	proc.Cmd = cmd
	
	stdout, _ := proc.Cmd.StdoutPipe()
	stderr, _ := proc.Cmd.StderrPipe()
	
	if err := proc.Cmd.Start(); err != nil {
		proc.Status = fmt.Sprintf("Error: %v", err)
		updateUI()
		return
	}
	
	proc.Status = "Running"
	proc.AddOutput(fmt.Sprintf("Started at %s", time.Now().Format("15:04:05")))
	
	go func() {
		scanner := io.MultiReader(stdout, stderr)
		buf := make([]byte, 1024)
		for {
			n, err := scanner.Read(buf)
			if n > 0 {
				lines := strings.Split(string(buf[:n]), "\n")
				for _, line := range lines {
					if line != "" {
						proc.AddOutput(line)
						updateUI()
					}
				}
			}
			if err != nil {
				break
			}
		}
	}()
	
	go func() {
		proc.Cmd.Wait()
		proc.Status = "Stopped"
		proc.AddOutput(fmt.Sprintf("Stopped at %s", time.Now().Format("15:04:05")))
		updateUI()
	}()
	
	updateUI()
}

func createProcessView() (*tview.Grid, func()) {
	grid := tview.NewGrid().
		SetRows(0, 0, 0).
		SetColumns(0)
	
	textViews := make([]*tview.TextView, len(processes))
	for i := range processes {
		textViews[i] = tview.NewTextView().
			SetDynamicColors(true).
			SetScrollable(true).
			SetChangedFunc(func() {
				app.Draw()
			})
		grid.AddItem(textViews[i], i, 0, 1, 1, 0, 0, false)
	}
	
	updateProcessUI := func() {
		for i, proc := range processes {
			output := proc.GetOutput()
			lastLines := output
			if len(lastLines) > 15 {
				lastLines = lastLines[len(lastLines)-15:]
			}
			
			color := "red"
			if proc.Status == "Running" {
				color = "green"
			}
			
			content := fmt.Sprintf("[white::b]%s[-] [%s]%s[-]\n\n", proc.Name, color, proc.Status)
			if len(lastLines) > 0 {
				content += "[gray]" + strings.Join(lastLines, "\n") + "[-]"
			}
			textViews[i].SetText(content)
		}
	}
	
	// Update periodically
	go func() {
		for {
			time.Sleep(1 * time.Second)
			updateProcessUI()
		}
	}()
	
	return grid, updateProcessUI
}

func createDashboard() *tview.Flex {
	flex := tview.NewFlex().SetDirection(tview.FlexRow)
	
	// Stats panel
	statsView := tview.NewTextView().
		SetDynamicColors(true).
		SetScrollable(false)
	
	// Members list
	membersView := tview.NewTextView().
		SetDynamicColors(true).
		SetScrollable(true)
	
	// Vendors list
	vendorsView := tview.NewTextView().
		SetDynamicColors(true).
		SetScrollable(true)
	
	// Transactions list
	txView := tview.NewTextView().
		SetDynamicColors(true).
		SetScrollable(true)
	
	updateDashboard := func() {
		state.mu.RLock()
		defer state.mu.RUnlock()
		
		// Stats
		stats := fmt.Sprintf(
			"[yellow::b]═══ COMMUNITY STATS ═══[-]\n"+
			"[cyan]Members:[-] %d\n"+
			"[cyan]Vendors:[-] %d\n"+
			"[cyan]UBI Amount:[-] %s units\n"+
			"[cyan]UBI Interval:[-] %s\n"+
			"[cyan]Last UBI:[-] %s\n"+
			"[cyan]Next UBI:[-] %s\n"+
			"[cyan]Total Transactions:[-] %d\n"+
			"[cyan]Total Purchases:[-] %d\n",
			len(state.Members),
			len(state.Vendors),
			state.UBIAmount,
			state.UBIInterval.String(),
			state.LastUBI.Format("15:04:05"),
			state.LastUBI.Add(state.UBIInterval).Format("15:04:05"),
			len(state.Transactions),
			len(state.Purchases),
		)
		statsView.SetText(stats)
		
		// Members
		members := "[yellow::b]═══ MEMBERS ═══[-]\n"
		for addr, member := range state.Members {
			balance, _ := getBalance(addr)
			vendorTag := ""
			if member.IsVendor {
				vendorTag = " [green][VENDOR][-]"
			}
			members += fmt.Sprintf(
				"[cyan]%s...%s[-]%s\n  Joined: %s | Balance: %s\n",
				addr[:6], addr[len(addr)-4:],
				vendorTag,
				member.JoinDate.Format("2006-01-02"),
				balance,
			)
		}
		membersView.SetText(members)
		
		// Vendors
		vendors := "[yellow::b]═══ VENDORS ═══[-]\n"
		for _, vendor := range state.Vendors {
			status := "[red]INACTIVE[-]"
			if vendor.Active {
				status = "[green]ACTIVE[-]"
			}
			vendors += fmt.Sprintf(
				"[cyan::b]%s[-] %s\n  %s\n  Items: %d | API: %s...\n",
				vendor.Name,
				status,
				vendor.Description,
				len(vendor.Items),
				vendor.APIKey[:8],
			)
		}
		if len(state.Vendors) == 0 {
			vendors += "[gray]No vendors registered[-]\n"
		}
		vendorsView.SetText(vendors)
		
		// Recent transactions
		txList := "[yellow::b]═══ RECENT TRANSACTIONS ═══[-]\n"
		start := len(state.Transactions) - 10
		if start < 0 {
			start = 0
		}
		for _, tx := range state.Transactions[start:] {
			typeColor := "white"
			if tx.Type == "UBI" {
				typeColor = "green"
			} else if tx.Type == "purchase" {
				typeColor = "yellow"
			}
			txList += fmt.Sprintf(
				"[%s][%s][-] %s → %s: %s units\n",
				tx.Timestamp.Format("15:04:05"),
				typeColor, tx.Type,
				tx.From[:8]+"...",
				tx.To[:8]+"...",
				tx.Amount,
			)
		}
		txView.SetText(txList)
	}
	
	// Update dashboard periodically
	go func() {
		for {
			time.Sleep(5 * time.Second)
			updateDashboard()
			app.Draw()
		}
	}()
	
	flex.AddItem(statsView, 12, 0, false).
		AddItem(tview.NewFlex().
			AddItem(membersView, 0, 1, false).
			AddItem(vendorsView, 0, 1, false), 0, 1, false).
		AddItem(txView, 0, 1, false)
	
	updateDashboard()
	return flex
}

func createMemberForm() *tview.Form {
	form := tview.NewForm()
	form.SetBorder(true).SetTitle(" Add New Member ").SetTitleAlign(tview.AlignLeft)
	
	var name string
	
	form.AddInputField("Name", "", 30, nil, func(text string) {
		name = text
	})
	
	form.AddButton("Create Wallet", func() {
		if name == "" {
			return
		}
		
		wallet, err := createWallet()
		if err != nil {
			return
		}
		
		state.mu.Lock()
		state.Members[wallet.Address] = &Member{
			Address:   wallet.Address,
			Name:      name,
			Mnemonic:  wallet.Mnemonic,
			JoinDate:  time.Now(),
			Balance:   "0",
			LastUBI:   time.Time{},
			IsVendor:  false,
			VendorKey: "",
		}
		state.mu.Unlock()
		saveState()
		
		// Show wallet info
		modal := tview.NewModal().
			SetText(fmt.Sprintf(
				"Wallet Created for %s!\n\n"+
				"Address: %s\n\n"+
				"Mnemonic:\n%s\n\n"+
				"[yellow]Mnemonic has been backed up in the system[-]\n"+
				"[gray]Press 'W' to view wallet backups anytime[-]",
				name,
				wallet.Address,
				wallet.Mnemonic,
			)).
			AddButtons([]string{"OK"}).
			SetDoneFunc(func(buttonIndex int, buttonLabel string) {
				pages.SwitchToPage("dashboard")
			})
		
		pages.AddPage("wallet-info", modal, true, true)
	})
	
	form.AddButton("Cancel", func() {
		pages.SwitchToPage("dashboard")
	})
	
	return form
}

func createVendorForm() *tview.Form {
	form := tview.NewForm()
	form.SetBorder(true).SetTitle(" Register Vendor ").SetTitleAlign(tview.AlignLeft)
	
	var address, name, description string
	
	form.AddInputField("Member Address", "", 50, nil, func(text string) {
		address = text
	})
	
	form.AddInputField("Business Name", "", 40, nil, func(text string) {
		name = text
	})
	
	form.AddInputField("Description", "", 60, nil, func(text string) {
		description = text
	})
	
	form.AddButton("Register", func() {
		if address == "" || name == "" {
			return
		}
		
		state.mu.Lock()
		member, exists := state.Members[address]
		if !exists {
			state.mu.Unlock()
			return
		}
		
		apiKey := generateAPIKey()
		
		state.Vendors[address] = &Vendor{
			Address:     address,
			Name:        name,
			Description: description,
			Items:       []Item{},
			APIKey:      apiKey,
			Active:      true,
			JoinDate:    time.Now(),
		}
		
		member.IsVendor = true
		member.VendorKey = apiKey
		state.mu.Unlock()
		saveState()
		
		// Show API key
		modal := tview.NewModal().
			SetText(fmt.Sprintf(
				"Vendor Registered!\n\n"+
				"Business: %s\n"+
				"API Key: %s\n\n"+
				"[yellow]SAVE THIS API KEY![-]\n"+
				"Use it for marketplace API access",
				name, apiKey,
			)).
			AddButtons([]string{"OK"}).
			SetDoneFunc(func(buttonIndex int, buttonLabel string) {
				pages.SwitchToPage("dashboard")
			})
		
		pages.AddPage("vendor-info", modal, true, true)
	})
	
	form.AddButton("Cancel", func() {
		pages.SwitchToPage("dashboard")
	})
	
	return form
}

func createMarketplaceView() *tview.Flex {
	flex := tview.NewFlex().SetDirection(tview.FlexRow)
	
	vendorList := tview.NewTextView().
		SetDynamicColors(true).
		SetScrollable(true)
	
	itemList := tview.NewTextView().
		SetDynamicColors(true).
		SetScrollable(true)
	
	updateMarketplace := func() {
		state.mu.RLock()
		defer state.mu.RUnlock()
		
		vendors := "[yellow::b]═══ MARKETPLACE - VENDORS ═══[-]\n\n"
		items := "[yellow::b]═══ AVAILABLE ITEMS ═══[-]\n\n"
		
		for _, vendor := range state.Vendors {
			if !vendor.Active {
				continue
			}
			
			vendors += fmt.Sprintf(
				"[cyan::b]%s[-]\n"+
				"  %s\n"+
				"  Address: %s...%s\n"+
				"  Items: %d\n\n",
				vendor.Name,
				vendor.Description,
				vendor.Address[:6], vendor.Address[len(vendor.Address)-4:],
				len(vendor.Items),
			)
			
			for _, item := range vendor.Items {
				if !item.Available || item.Stock <= 0 {
					continue
				}
				
				items += fmt.Sprintf(
					"[white::b]%s[-] - %s units\n"+
					"  %s\n"+
					"  Stock: %d | Vendor: %s\n"+
					"  ID: %s\n\n",
					item.Name, item.Price,
					item.Description,
					item.Stock, vendor.Name,
					item.ID,
				)
			}
		}
		
		if len(state.Vendors) == 0 {
			vendors += "[gray]No vendors registered[-]\n"
		}
		
		vendorList.SetText(vendors)
		itemList.SetText(items)
	}
	
	go func() {
		for {
			time.Sleep(5 * time.Second)
			updateMarketplace()
			app.Draw()
		}
	}()
	
	flex.AddItem(vendorList, 0, 1, false).
		AddItem(itemList, 0, 1, false)
	
	updateMarketplace()
	return flex
}

func createWalletBackupsView() *tview.Flex {
	flex := tview.NewFlex().SetDirection(tview.FlexColumn)
	
	memberList := tview.NewList()
	
	detailView := tview.NewTextView().
		SetDynamicColors(true).
		SetScrollable(true).
		SetWordWrap(true)
	
	detailView.SetBorder(true).SetTitle(" Wallet Details ").SetTitleAlign(tview.AlignLeft)
	
	var members []string
	
	updateWalletList := func() {
		state.mu.RLock()
		defer state.mu.RUnlock()
		
		memberList.Clear()
		members = make([]string, 0)
		
		if len(state.Members) == 0 {
			detailView.SetText("[gray]No members registered yet[-]")
			return
		}
		
		for addr, member := range state.Members {
			name := member.Name
			if name == "" {
				name = addr[:8] + "..."
			}
			
			vendorTag := ""
			if member.IsVendor {
				vendorTag = " [VENDOR]"
			}
			
			members = append(members, addr)
			
			memberList.AddItem(name+vendorTag, addr[:16]+"...", 0, nil)
		}
		
		// Show first member by default
		if memberList.GetItemCount() > 0 {
			showMemberDetails(0)
		}
	}
	
	showMemberDetails := func(idx int) {
		if idx < 0 || idx >= len(members) {
			return
		}
		
		state.mu.RLock()
		defer state.mu.RUnlock()
		
		selectedAddr := members[idx]
		m := state.Members[selectedAddr]
		
		details := fmt.Sprintf(
			"[yellow::b]Member Details[-]\n\n"+
			"[cyan]Name:[-] %s\n"+
			"[cyan]Address:[-] %s\n\n"+
			"[cyan]Mnemonic Phrase:[-]\n[white]%s[-]\n\n"+
			"[cyan]Join Date:[-] %s\n"+
			"[cyan]Vendor:[-] %v\n",
			m.Name,
			m.Address,
			m.Mnemonic,
			m.JoinDate.Format("2006-01-02 15:04:05"),
			m.IsVendor,
		)
		
		if m.IsVendor {
			details += fmt.Sprintf("[cyan]Vendor API Key:[-] %s\n", m.VendorKey)
		}
		
		detailView.SetText(details)
	}
	
	memberList.SetChangedFunc(func(index int, mainText string, secondaryText string, shortcut rune) {
		showMemberDetails(index)
	})
	
	updateWalletList()
	
	memberList.SetBorder(true).SetTitle(" Members ").SetTitleAlign(tview.AlignLeft)
	
	flex.AddItem(memberList, 0, 1, true).
		AddItem(detailView, 0, 2, false)
	
	return flex
}

func main() {
	initCommunityState()
	
	app = tview.NewApplication()
	pages = tview.NewPages()
	
	// Extract embedded binaries
	tmpDir, err := os.MkdirTemp("", "core-wrapper-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create temp dir: %v\n", err)
		os.Exit(1)
	}
	defer os.RemoveAll(tmpDir)

	programs := []string{"wolfether", "atr-net", "digitz"}
	processes = make([]*ProcessInfo, len(programs))
	
	for i, prog := range programs {
		processes[i] = &ProcessInfo{
			Name:   prog,
			Status: "Stopped",
			Output: []string{},
		}
		
		data, err := embeddedFS.ReadFile("embedded/" + prog)
		if err != nil {
			processes[i].Status = fmt.Sprintf("Error: %v", err)
			continue
		}
		
		binPath := filepath.Join(tmpDir, prog)
		if err := os.WriteFile(binPath, data, 0755); err != nil {
			processes[i].Status = fmt.Sprintf("Error: %v", err)
			continue
		}
	}

	// Create main layout
	mainFlex := tview.NewFlex().SetDirection(tview.FlexRow)
	
	// Header
	header := tview.NewTextView().
		SetText("[yellow::b]WolfTech Innovations | The Core[-]\n[gray]P: Processes | D: Dashboard | M: Add Member | V: Register Vendor | K: Marketplace | W: Wallets | U: UBI | Q: Quit[-]").
		SetDynamicColors(true).
		SetTextAlign(tview.AlignCenter)
	
	// Create views
	processView, updateProcessUI := createProcessView()
	_ = updateProcessUI // Keep the update function available
	dashboardView := createDashboard()
	memberForm := createMemberForm()
	vendorForm := createVendorForm()
	marketplaceView := createMarketplaceView()
	walletBackupsView := createWalletBackupsView()
	
	// Content area
	contentPages := tview.NewPages()
	contentPages.AddPage("processes", processView, true, true)
	contentPages.AddPage("dashboard", dashboardView, true, false)
	contentPages.AddPage("add-member", memberForm, true, false)
	contentPages.AddPage("register-vendor", vendorForm, true, false)
	contentPages.AddPage("marketplace", marketplaceView, true, false)
	contentPages.AddPage("wallets", walletBackupsView, true, false)
	
	// Footer
	footer := tview.NewTextView().
		SetDynamicColors(true).
		SetTextAlign(tview.AlignCenter)
	
	updateFooter := func() {
		running := 0
		for _, proc := range processes {
			if proc.Status == "Running" {
				running++
			}
		}
		state.mu.RLock()
		memberCount := len(state.Members)
		state.mu.RUnlock()
		
		processStatus := ""
		for i, proc := range processes {
			if i > 0 {
				processStatus += " | "
			}
			color := "red"
			if proc.Status == "Running" {
				color = "green"
			}
			processStatus += fmt.Sprintf("[%s]%s[-]", color, proc.Name)
		}
		
		footer.SetText(fmt.Sprintf("%s | [cyan]Members: %d | Next UBI: %s[-]", 
			processStatus, memberCount, 
			state.LastUBI.Add(state.UBIInterval).Format("15:04:05")))
	}
	
	go func() {
		for {
			time.Sleep(1 * time.Second)
			updateFooter()
			app.Draw()
		}
	}()
	
	mainFlex.AddItem(header, 3, 0, false).
		AddItem(contentPages, 0, 1, true).
		AddItem(footer, 1, 0, false)
	
	pages.AddPage("main", mainFlex, true, true)
	
	// Start UBI distribution daemon
	go func() {
		for {
			time.Sleep(1 * time.Minute)
			distributeUBI()
		}
	}()
	
	// Keyboard controls
	app.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		switch event.Rune() {
		case 'q', 'Q':
			for _, proc := range processes {
				if proc.Cmd != nil && proc.Status == "Running" {
					proc.Cmd.Process.Kill()
				}
			}
			app.Stop()
			return nil
		case 'p', 'P':
			contentPages.SwitchToPage("processes")
		case 'd', 'D':
			contentPages.SwitchToPage("dashboard")
		case 'm', 'M':
			contentPages.SwitchToPage("add-member")
		case 'v', 'V':
			contentPages.SwitchToPage("register-vendor")
		case 'k', 'K':
			contentPages.SwitchToPage("marketplace")
		case 'w', 'W':
			contentPages.SwitchToPage("wallets")
		case 'u', 'U':
			distributeUBI()
		case '1':
			if processes[0].Status == "Running" {
				processes[0].Cmd.Process.Kill()
			} else {
				go startProcessMonitor(0, tmpDir, func() { app.Draw() })
			}
		case '2':
			if processes[1].Status == "Running" {
				processes[1].Cmd.Process.Kill()
			} else {
				go startProcessMonitor(1, tmpDir, func() { app.Draw() })
			}
		case '3':
			if processes[2].Status == "Running" {
				processes[2].Cmd.Process.Kill()
			} else {
				go startProcessMonitor(2, tmpDir, func() { app.Draw() })
			}
		case 's', 'S':
			for i := range processes {
				if processes[i].Status != "Running" {
					go startProcessMonitor(i, tmpDir, func() { app.Draw() })
				}
			}
		}
		return event
	}))
	
	// Auto-start WolfEther
	go func() {
		time.Sleep(1 * time.Second)
		startProcessMonitor(0, tmpDir, func() { app.Draw() })
	}()
	
	updateFooter()
	
	if err := app.SetRoot(pages, true).Run(); err != nil {
		panic(err)
	}
}