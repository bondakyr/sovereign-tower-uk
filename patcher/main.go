// Український локалізатор для Sovereign Tower.
//
// Патчить sovereign_tower.pck на місці: нові дані дописуються в кінець файлу,
// каталог PCK перебудовується. Оригінальні байти файлів не чіпаються, тож
// відкат повний і миттєвий.
package main

import (
	"crypto/md5"
	"embed"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

//go:embed payload/* manifest.json
var pkg embed.FS

const (
	magic           = "GDPC"
	pckFormatV3     = 3
	flagRelFileBase = 2
	alignTo         = 16
	backupSuffix    = ".uk_backup"
)

type manifestEntry struct {
	Path    string `json:"path"`
	File    string `json:"file"`
	Size    uint64 `json:"size"`
	MD5New  string `json:"md5_new"`
	MD5From string `json:"md5_from"`
	Action  string `json:"action"`
}

type manifest struct {
	Game    string          `json:"game"`
	Locale  string          `json:"locale"`
	Entries []manifestEntry `json:"entries"`
}

type dirEntry struct {
	path  string
	off   uint64 // relative to fileBase
	size  uint64
	md5   [16]byte
	flags uint32
}

type pck struct {
	f        *os.File
	fileBase uint64
	dirOff   uint64
	entries  []dirEntry
	byPath   map[string]int
	size     uint64
}

func die(format string, a ...any) {
	fmt.Printf("\n[!] "+format+"\n", a...)
	fmt.Print("\nНатисніть Enter, щоб вийти...")
	fmt.Scanln()
	os.Exit(1)
}

func openPck(path string, write bool) (*pck, error) {
	mode := os.O_RDONLY
	if write {
		mode = os.O_RDWR
	}
	f, err := os.OpenFile(path, mode, 0o644)
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	hdr := make([]byte, 40)
	if _, err := io.ReadFull(f, hdr); err != nil {
		return nil, fmt.Errorf("не вдалося прочитати заголовок: %w", err)
	}
	if string(hdr[0:4]) != magic {
		return nil, errors.New("це не файл .pck (немає сигнатури GDPC)")
	}
	if v := binary.LittleEndian.Uint32(hdr[4:8]); v != pckFormatV3 {
		return nil, fmt.Errorf("непідтримуваний формат PCK: %d (очікується %d)", v, pckFormatV3)
	}
	flags := binary.LittleEndian.Uint32(hdr[20:24])
	if flags&flagRelFileBase == 0 {
		return nil, errors.New("несподівані прапорці PCK: немає відносної адресації")
	}
	p := &pck{
		f:        f,
		fileBase: binary.LittleEndian.Uint64(hdr[24:32]),
		dirOff:   binary.LittleEndian.Uint64(hdr[32:40]),
		byPath:   map[string]int{},
		size:     uint64(st.Size()),
	}
	if p.dirOff >= p.size {
		return nil, errors.New("каталог PCK виходить за межі файлу — файл пошкоджений або обрізаний")
	}
	if _, err := f.Seek(int64(p.dirOff), io.SeekStart); err != nil {
		return nil, err
	}
	raw, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}
	if len(raw) < 4 {
		return nil, errors.New("каталог PCK порожній")
	}
	n := binary.LittleEndian.Uint32(raw[0:4])
	pos := 4
	for i := uint32(0); i < n; i++ {
		if pos+4 > len(raw) {
			return nil, errors.New("каталог PCK обірвано")
		}
		pl := int(binary.LittleEndian.Uint32(raw[pos : pos+4]))
		pos += 4
		if pl < 0 || pos+pl+36 > len(raw) {
			return nil, errors.New("пошкоджений запис у каталозі PCK")
		}
		name := strings.TrimRight(string(raw[pos:pos+pl]), "\x00")
		pos += pl
		var e dirEntry
		e.path = name
		e.off = binary.LittleEndian.Uint64(raw[pos : pos+8])
		e.size = binary.LittleEndian.Uint64(raw[pos+8 : pos+16])
		copy(e.md5[:], raw[pos+16:pos+32])
		e.flags = binary.LittleEndian.Uint32(raw[pos+32 : pos+36])
		pos += 36
		p.byPath[name] = len(p.entries)
		p.entries = append(p.entries, e)
	}
	return p, nil
}

func (p *pck) hashEntry(i int) (string, error) {
	e := p.entries[i]
	if _, err := p.f.Seek(int64(e.off+p.fileBase), io.SeekStart); err != nil {
		return "", err
	}
	h := md5.New()
	if _, err := io.CopyN(h, p.f, int64(e.size)); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func (p *pck) writeDirectory(at uint64) (uint64, error) {
	if _, err := p.f.Seek(int64(at), io.SeekStart); err != nil {
		return 0, err
	}
	buf := make([]byte, 0, 64*len(p.entries))
	var u32 [4]byte
	var u64 [8]byte
	binary.LittleEndian.PutUint32(u32[:], uint32(len(p.entries)))
	buf = append(buf, u32[:]...)
	for _, e := range p.entries {
		name := []byte(e.path)
		padded := (len(name) + 3) / 4 * 4
		if padded == len(name) {
			padded += 4 // Godot завжди лишає принаймні один нуль-термінатор
		}
		binary.LittleEndian.PutUint32(u32[:], uint32(padded))
		buf = append(buf, u32[:]...)
		buf = append(buf, name...)
		buf = append(buf, make([]byte, padded-len(name))...)
		binary.LittleEndian.PutUint64(u64[:], e.off)
		buf = append(buf, u64[:]...)
		binary.LittleEndian.PutUint64(u64[:], e.size)
		buf = append(buf, u64[:]...)
		buf = append(buf, e.md5[:]...)
		binary.LittleEndian.PutUint32(u32[:], e.flags)
		buf = append(buf, u32[:]...)
	}
	if _, err := p.f.Write(buf); err != nil {
		return 0, err
	}
	return at + uint64(len(buf)), nil
}

func (p *pck) setDirOffset(off uint64) error {
	var u64 [8]byte
	binary.LittleEndian.PutUint64(u64[:], off)
	_, err := p.f.WriteAt(u64[:], 32)
	return err
}

func loadManifest() manifest {
	raw, err := pkg.ReadFile("manifest.json")
	if err != nil {
		die("пошкоджено вбудований маніфест: %v", err)
	}
	var m manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		die("пошкоджено вбудований маніфест: %v", err)
	}
	return m
}

func findPck(explicit string) string {
	if explicit != "" {
		return explicit
	}
	var roots []string
	if exe, err := os.Executable(); err == nil {
		roots = append(roots, filepath.Dir(exe))
	}
	if wd, err := os.Getwd(); err == nil {
		roots = append(roots, wd)
	}
	roots = append(roots,
		`C:\Program Files (x86)\Steam\steamapps\common\Sovereign Tower\sovereign_tower_windows_build`,
		`C:\Program Files\Steam\steamapps\common\Sovereign Tower\sovereign_tower_windows_build`,
	)
	for _, r := range roots {
		c := filepath.Join(r, "sovereign_tower.pck")
		if st, err := os.Stat(c); err == nil && !st.IsDir() {
			return c
		}
	}
	return ""
}

func verify(p *pck, m manifest) (ok []manifestEntry, missing, mismatched []manifestEntry) {
	for _, e := range m.Entries {
		if e.Action == "add" {
			if _, exists := p.byPath[e.Path]; exists {
				mismatched = append(mismatched, e) // вже пропатчено?
				continue
			}
			ok = append(ok, e)
			continue
		}
		i, exists := p.byPath[e.Path]
		if !exists {
			missing = append(missing, e)
			continue
		}
		got, err := p.hashEntry(i)
		if err != nil {
			missing = append(missing, e)
			continue
		}
		if got == e.MD5New {
			continue // вже на місці
		}
		if got != e.MD5From {
			mismatched = append(mismatched, e)
			continue
		}
		ok = append(ok, e)
	}
	return
}

func shortPaths(es []manifestEntry, max int) string {
	var b strings.Builder
	sort.Slice(es, func(i, j int) bool { return es[i].Path < es[j].Path })
	for i, e := range es {
		if i >= max {
			fmt.Fprintf(&b, "      ... і ще %d\n", len(es)-max)
			break
		}
		fmt.Fprintf(&b, "      %s\n", e.Path)
	}
	return b.String()
}

func install(pckPath string, m manifest, force bool) {
	if _, err := os.Stat(pckPath + backupSuffix); err == nil {
		die("Локалізацію вже встановлено (є файл %s).\n"+
			"    Щоб перевстановити — спершу запустіть з ключем -uninstall", filepath.Base(pckPath+backupSuffix))
	}

	p, err := openPck(pckPath, true)
	if err != nil {
		die("%v", err)
	}
	defer p.f.Close()

	fmt.Printf("    Файл гри : %s\n", pckPath)
	fmt.Printf("    Записів  : %d, розмір %.2f ГБ\n\n", len(p.entries), float64(p.size)/(1<<30))
	fmt.Println("[1/4] Перевірка сумісності...")

	ok, missing, mismatched := verify(p, m)

	if len(missing) > 0 {
		fmt.Printf("\n    Не знайдено у вашій версії гри (%d):\n%s", len(missing), shortPaths(missing, 10))
	}
	if len(mismatched) > 0 {
		fmt.Printf("\n    Змінено оновленням гри (%d):\n%s", len(mismatched), shortPaths(mismatched, 10))
	}
	if len(missing) > 0 || len(mismatched) > 0 {
		fmt.Println("\n    Ці файли відрізняються від тієї збірки, на якій зроблено переклад.")
		fmt.Println("    Якщо їх замінити, гра відкотиться до старішої версії цих файлів.")
		if !force {
			die("Встановлення припинено. Потрібна збірка локалізації під вашу версію гри.\n" +
				"    (Якщо ви точно знаєте, що робите, можна запустити з ключем -force)")
		}
		fmt.Println("\n    -force: продовжую попри розбіжності.")
		ok = append(ok, mismatched...)
	}
	if len(ok) == 0 {
		fmt.Println("\n[✓] Нічого робити — локалізація вже на місці.")
		return
	}

	fmt.Printf("    Готово до запису: %d файлів\n\n", len(ok))

	fmt.Println("[2/4] Створення резервної копії каталогу...")
	if _, err := p.f.Seek(int64(p.dirOff), io.SeekStart); err != nil {
		die("%v", err)
	}
	oldDir, err := io.ReadAll(p.f)
	if err != nil {
		die("%v", err)
	}
	bak, err := os.Create(pckPath + backupSuffix)
	if err != nil {
		die("не вдалося створити резервну копію: %v\n    Запустіть від імені адміністратора.", err)
	}
	var hdrBak [8]byte
	binary.LittleEndian.PutUint64(hdrBak[:], p.dirOff)
	if _, err := bak.Write(hdrBak[:]); err != nil {
		die("%v", err)
	}
	if _, err := bak.Write(oldDir); err != nil {
		die("%v", err)
	}
	bak.Close()
	fmt.Printf("    %s (%.1f МБ)\n\n", filepath.Base(pckPath+backupSuffix), float64(len(oldDir)+8)/(1<<20))

	fmt.Println("[3/4] Запис даних локалізації...")
	pos := (p.dirOff + alignTo - 1) / alignTo * alignTo
	for _, e := range ok {
		data, err := pkg.ReadFile("payload/" + e.File)
		if err != nil {
			die("пошкоджено вбудовані дані (%s): %v", e.File, err)
		}
		sum := md5.Sum(data)
		if hex.EncodeToString(sum[:]) != e.MD5New {
			die("пошкоджено вбудовані дані: %s", e.Path)
		}
		if _, err := p.f.Seek(int64(pos), io.SeekStart); err != nil {
			die("%v", err)
		}
		if _, err := p.f.Write(data); err != nil {
			die("помилка запису: %v\n    Перевірте вільне місце і права доступу.", err)
		}
		ne := dirEntry{path: e.Path, off: pos - p.fileBase, size: uint64(len(data)), md5: sum, flags: 0}
		if i, exists := p.byPath[e.Path]; exists {
			ne.flags = p.entries[i].flags
			p.entries[i] = ne
		} else {
			p.byPath[e.Path] = len(p.entries)
			p.entries = append(p.entries, ne)
		}
		pos += uint64(len(data))
		pos = (pos + alignTo - 1) / alignTo * alignTo
	}
	fmt.Printf("    Записано %d файлів\n\n", len(ok))

	fmt.Println("[4/4] Перебудова каталогу...")
	end, err := p.writeDirectory(pos)
	if err != nil {
		die("%v", err)
	}
	if err := p.setDirOffset(pos); err != nil {
		die("%v", err)
	}
	if err := p.f.Truncate(int64(end)); err != nil {
		die("%v", err)
	}
	if err := p.f.Sync(); err != nil {
		die("%v", err)
	}
	fmt.Printf("    Каталог: %d записів\n\n", len(p.entries))

	fmt.Println("[✓] Готово. Запустіть гру і виберіть українську в налаштуваннях.")
	fmt.Println("    Відкотити: запустити цю програму з ключем -uninstall")
}

func uninstall(pckPath string) {
	bakPath := pckPath + backupSuffix
	raw, err := os.ReadFile(bakPath)
	if err != nil {
		die("Резервну копію не знайдено (%s).\n    Відкотити нічим — перевстановіть гру через Steam.", filepath.Base(bakPath))
	}
	if len(raw) < 8 {
		die("резервна копія пошкоджена")
	}
	oldDirOff := binary.LittleEndian.Uint64(raw[0:8])
	oldDir := raw[8:]

	f, err := os.OpenFile(pckPath, os.O_RDWR, 0o644)
	if err != nil {
		die("%v\n    Запустіть від імені адміністратора.", err)
	}
	defer f.Close()

	fmt.Println("[1/2] Відновлення каталогу...")
	if _, err := f.WriteAt(oldDir, int64(oldDirOff)); err != nil {
		die("%v", err)
	}
	var u64 [8]byte
	binary.LittleEndian.PutUint64(u64[:], oldDirOff)
	if _, err := f.WriteAt(u64[:], 32); err != nil {
		die("%v", err)
	}
	if err := f.Truncate(int64(oldDirOff) + int64(len(oldDir))); err != nil {
		die("%v", err)
	}
	if err := f.Sync(); err != nil {
		die("%v", err)
	}

	fmt.Println("[2/2] Прибирання...")
	f.Close()
	os.Remove(bakPath)
	fmt.Println("\n[✓] Локалізацію вилучено, гра повернулася до оригінального стану.")
}

// export витягує з .pck користувача саме ті файли, які локалізація замінює.
// Потрібно, щоб зібрати переклад під нову версію гри, не передаючи весь архів.
func export(pckPath string, m manifest) {
	p, err := openPck(pckPath, false)
	if err != nil {
		die("%v", err)
	}
	defer p.f.Close()

	outDir := "uk_export"
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		die("не вдалося створити теку %s: %v", outDir, err)
	}
	fmt.Printf("    Файл гри : %s\n\n", pckPath)
	fmt.Println("[1/2] Витягування файлів...")

	type rec struct {
		Path string `json:"path"`
		File string `json:"file"`
		Size uint64 `json:"size"`
		MD5  string `json:"md5"`
	}
	var index []rec
	var total uint64
	for _, e := range m.Entries {
		if e.Action != "replace" {
			continue
		}
		i, exists := p.byPath[e.Path]
		if !exists {
			continue
		}
		ent := p.entries[i]
		if _, err := p.f.Seek(int64(ent.off+p.fileBase), io.SeekStart); err != nil {
			die("%v", err)
		}
		data := make([]byte, ent.size)
		if _, err := io.ReadFull(p.f, data); err != nil {
			die("%v", err)
		}
		if err := os.WriteFile(filepath.Join(outDir, e.File), data, 0o644); err != nil {
			die("%v", err)
		}
		sum := md5.Sum(data)
		index = append(index, rec{e.Path, e.File, ent.size, hex.EncodeToString(sum[:])})
		total += ent.size
	}
	fmt.Printf("    Витягнуто %d файлів, %.2f МБ\n\n", len(index), float64(total)/(1<<20))

	fmt.Println("[2/2] Запис опису...")
	meta := map[string]any{
		"pck_entries": len(p.entries),
		"pck_size":    p.size,
		"files":       index,
	}
	raw, _ := json.MarshalIndent(meta, "", " ")
	if err := os.WriteFile(filepath.Join(outDir, "index.json"), raw, 0o644); err != nil {
		die("%v", err)
	}

	fmt.Printf("\n[✓] Готово: тека %s\n", outDir)
	fmt.Println("    Заархівуйте її і надішліть — цього досить, щоб зібрати")
	fmt.Println("    локалізацію під вашу версію гри.")
}

func check(pckPath string, m manifest) {
	p, err := openPck(pckPath, false)
	if err != nil {
		die("%v", err)
	}
	defer p.f.Close()
	fmt.Printf("    Файл гри : %s\n", pckPath)
	fmt.Printf("    Записів  : %d, розмір %.2f ГБ\n\n", len(p.entries), float64(p.size)/(1<<30))

	ok, missing, mismatched := verify(p, m)
	fmt.Printf("    Можна застосувати : %d\n", len(ok))
	fmt.Printf("    Відсутні          : %d\n", len(missing))
	fmt.Printf("    Змінені оновленням: %d\n\n", len(mismatched))
	if len(missing) > 0 {
		fmt.Printf("    Відсутні:\n%s\n", shortPaths(missing, 100))
	}
	if len(mismatched) > 0 {
		fmt.Printf("    Змінені:\n%s\n", shortPaths(mismatched, 100))
	}
	if len(missing) == 0 && len(mismatched) == 0 {
		fmt.Println("[✓] Версія гри сумісна — можна встановлювати.")
	} else {
		fmt.Println("[!] Версія гри відрізняється від тієї, на якій зроблено переклад.")
	}
}

func main() {
	setupConsole()

	var (
		pckFlag  = flag.String("pck", "", "шлях до sovereign_tower.pck")
		doRemove = flag.Bool("uninstall", false, "відкотити локалізацію")
		doCheck  = flag.Bool("check", false, "лише перевірити сумісність, нічого не змінювати")
		doExport = flag.Bool("export", false, "витягти файли, які замінює локалізація (для перезбірки)")
		doForce  = flag.Bool("force", false, "встановити попри розбіжності версій")
		noPause  = flag.Bool("nopause", false, "не чекати Enter наприкінці")
	)
	flag.Parse()

	m := loadManifest()
	fmt.Println()
	fmt.Println("  ╔══════════════════════════════════════════════════════╗")
	fmt.Println("  ║   Sovereign Tower — українська локалізація           ║")
	fmt.Println("  ╚══════════════════════════════════════════════════════╝")
	fmt.Println()

	pckPath := findPck(*pckFlag)
	if pckPath == "" {
		die("Не знайдено sovereign_tower.pck.\n" +
			"    Покладіть цю програму в папку з грою (поруч із sovereign_tower.exe)\n" +
			"    або вкажіть шлях: uk_patch.exe -pck \"C:\\...\\sovereign_tower.pck\"")
	}

	switch {
	case *doCheck:
		check(pckPath, m)
	case *doExport:
		export(pckPath, m)
	case *doRemove:
		uninstall(pckPath)
	default:
		install(pckPath, m, *doForce)
	}

	if !*noPause {
		fmt.Print("\nНатисніть Enter, щоб вийти...")
		fmt.Scanln()
	}
}
