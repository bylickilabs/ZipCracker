import pyzipper
import os
import time
import json
from rich.console import Console
from rich.progress import track
from rich.table import Table
from rich.prompt import Prompt, Confirm
from tqdm import tqdm

console = Console()
LOG_FILE = "crack_log.txt"
EXPORT_FILE = "result.json"

MESSAGES = {
    "en": {
        "menu_title": "ZIP Password Cracker Suite",
        "menu_dict": "[1] Dictionary Attack",
        "menu_brute": "[2] Brute-Force Attack",
        "menu_preview": "[3] Preview Wordlist",
        "menu_settings": "[4] Change Settings",
        "menu_info": "[5] Info & Help",
        "menu_lang": "[6] Change Language",
        "menu_exit": "[0] Exit",
        "prompt_choice": "Your choice",
        "prompt_zip": "ZIP file path",
        "prompt_wordlist": "Wordlist path",
        "prompt_charset": "Brute-force charset",
        "prompt_maxlen": "Brute-force max length",
        "prompt_dryrun": "Dry-run mode (simulate)?",
        "prompt_lang": "Select language",
        "lang_en": "English",
        "lang_de": "Deutsch",
        "msg_enc_detect": "Detecting encryption type...",
        "msg_enc_type": "Detected type",
        "msg_no_wordlist": "[red]Wordlist not found![/red]",
        "msg_preview": "Wordlist Preview (Top 20)",
        "msg_eta": "Estimated duration (20 pw/s)",
        "msg_start": "Start?",
        "msg_found": "[green]Password found:",
        "msg_notfound": "[red]No password found.[/red]",
        "msg_log_saved": "[cyan]Log saved in",
        "msg_export_saved": "and result in",
        "msg_charset_info": "Brute-force charset",
        "msg_maxlen_info": "Max length",
        "msg_start_warn": "Start? (Warning: slow for 5+ chars)",
        "msg_info": "[green]Python CLI Suite for ZIP password cracking via dictionary and brute-force.[/green]",
        "msg_exit": "Goodbye!",
        "msg_resume": "Resume from which password index? (0 = from start)",
        "msg_preview_done": "[cyan]Preview complete.[/cyan]",
    },
    "de": {
        "menu_title": "ZIP Passwort Cracker Suite",
        "menu_dict": "[1] Wörterbuch-Angriff starten",
        "menu_brute": "[2] Brute-Force-Angriff starten",
        "menu_preview": "[3] Wörterliste Vorschau",
        "menu_settings": "[4] Einstellungen ändern",
        "menu_info": "[5] Info & Hilfe",
        "menu_lang": "[6] Sprache wechseln",
        "menu_exit": "[0] Beenden",
        "prompt_choice": "Ihre Auswahl",
        "prompt_zip": "ZIP-Datei Pfad",
        "prompt_wordlist": "Wörterlisten Pfad",
        "prompt_charset": "Brute-Force-Zeichensatz",
        "prompt_maxlen": "Brute-Force maximale Länge",
        "prompt_dryrun": "Dry-Run-Modus (Simulation)?",
        "prompt_lang": "Sprache wählen",
        "lang_en": "Englisch",
        "lang_de": "Deutsch",
        "msg_enc_detect": "Erkenne Verschlüsselungstyp...",
        "msg_enc_type": "Gefundener Typ",
        "msg_no_wordlist": "[red]Wörterliste nicht gefunden![/red]",
        "msg_preview": "Wörterliste Vorschau (Top 20)",
        "msg_eta": "Geschätzte Dauer (bei 20 Wörter/s)",
        "msg_start": "Starten?",
        "msg_found": "[green]Passwort gefunden:",
        "msg_notfound": "[red]Kein Passwort gefunden.[/red]",
        "msg_log_saved": "[cyan]Log gespeichert in",
        "msg_export_saved": "und Ergebnis in",
        "msg_charset_info": "Brute-Force-Zeichensatz",
        "msg_maxlen_info": "Maximale Länge",
        "msg_start_warn": "Starten? (Achtung: sehr langsam ab 5 Zeichen)",
        "msg_info": "[green]Python CLI-Suite zum Knacken geschützter ZIP-Archive mit Wörterbuch- und Brute-Force-Angriff.[/green]",
        "msg_exit": "Auf Wiedersehen!",
        "msg_resume": "Fortsetzen ab Passwort-Index? (0 = ab Anfang)",
        "msg_preview_done": "[cyan]Vorschau beendet.[/cyan]",
    }
}

def filter_wordlist(wordlist):
    return list({w for w in wordlist if w.strip() and len(w.strip()) >= 4})

def load_wordlist(path, lang):
    if not os.path.exists(path):
        console.print(MESSAGES[lang]["msg_no_wordlist"])
        return []
    with open(path, encoding="utf-8", errors="ignore") as f:
        lines = f.read().splitlines()
    return filter_wordlist(lines)

def preview_wordlist(wordlist, lang, n=20):
    table = Table(title=MESSAGES[lang]["msg_preview"])
    table.add_column("Nr", justify="right")
    table.add_column("Passwort")
    for idx, pwd in enumerate(wordlist[:n], 1):
        table.add_row(str(idx), pwd)
    console.print(table)
    console.print(MESSAGES[lang]["msg_preview_done"])

def detect_encryption(zipfile_path, lang):
    try:
        with pyzipper.AESZipFile(zipfile_path) as zf:
            for info in zf.infolist():
                if info.flag_bits & 0x40:
                    return "AES"
            return "ZipCrypto"
    except Exception as e:
        return f"Unknown/Unbekannt ({e})"

def try_password(zipfile_path, pwd, dryrun=False):
    try:
        if dryrun:
            time.sleep(0.01)
            return False
        with pyzipper.AESZipFile(zipfile_path) as zf:
            zf.pwd = pwd.encode("utf-8")
            zf.extractall("./temp_extract")
        return True
    except:
        return False

def brute_force_charset(length, charset):
    import itertools
    for l in range(1, length+1):
        for p in itertools.product(charset, repeat=l):
            yield ''.join(p)

def crack_dictionary(zipfile_path, wordlist, lang, dryrun=False, resume=0):
    start = time.time()
    log = []
    found = None
    total = len(wordlist)
    for idx, pwd in enumerate(tqdm(wordlist[resume:], desc="Teste Passwörter")):
        result = try_password(zipfile_path, pwd, dryrun=dryrun)
        log.append({'index': resume+idx+1, 'password': pwd, 'success': result})
        if result:
            found = pwd
            break
    dauer = time.time() - start
    return found, log, dauer

def crack_bruteforce(zipfile_path, charset, max_length, lang, dryrun=False, resume=0):
    start = time.time()
    log = []
    i = 0
    for pwd in brute_force_charset(max_length, charset):
        i += 1
        if i < resume:
            continue
        result = try_password(zipfile_path, pwd, dryrun=dryrun)
        log.append({'index': i, 'password': pwd, 'success': result})
        if result:
            dauer = time.time() - start
            return pwd, log, dauer
    dauer = time.time() - start
    return None, log, dauer

def save_log(log, found, dauer, mode, lang):
    with open(LOG_FILE, "w", encoding="utf-8") as f:
        for entry in log:
            f.write(json.dumps(entry) + "\n")
    with open(EXPORT_FILE, "w", encoding="utf-8") as f:
        result = {
            "found": found,
            "mode": mode,
            "dauer_sec": dauer,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "logfile": LOG_FILE
        }
        f.write(json.dumps(result, indent=2))
    return LOG_FILE, EXPORT_FILE

def choose_language(lang):
    console.print(f"[cyan][1] {MESSAGES['en']['lang_en']}[/cyan]")
    console.print(f"[cyan][2] {MESSAGES['de']['lang_de']}[/cyan]")
    sel = Prompt.ask(MESSAGES[lang]["prompt_lang"], choices=['1','2'], default='1')
    return "en" if sel == '1' else "de"

def show_menu(lang):
    console.print(f"\n[bold cyan]{MESSAGES[lang]['menu_title']}[/bold cyan]")
    console.print(MESSAGES[lang]['menu_dict'])
    console.print(MESSAGES[lang]['menu_brute'])
    console.print(MESSAGES[lang]['menu_preview'])
    console.print(MESSAGES[lang]['menu_settings'])
    console.print(MESSAGES[lang]['menu_info'])
    console.print(MESSAGES[lang]['menu_lang'])
    console.print(MESSAGES[lang]['menu_exit'])

def main():
    zipfile_path = "protected.zip"
    wordlist_path = "wordlist.txt"
    charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    max_length = 4
    dryrun = False
    resume = 0
    lang = "en"
    while True:
        show_menu(lang)
        choice = Prompt.ask(MESSAGES[lang]["prompt_choice"], choices=['0','1','2','3','4','5','6'])
        if choice == "0":
            console.print(MESSAGES[lang]["msg_exit"])
            break
        elif choice == "5":
            console.print(MESSAGES[lang]["msg_info"])
        elif choice == "6":
            lang = choose_language(lang)
        elif choice == "4":
            zipfile_path = Prompt.ask(MESSAGES[lang]["prompt_zip"], default=zipfile_path)
            wordlist_path = Prompt.ask(MESSAGES[lang]["prompt_wordlist"], default=wordlist_path)
            charset = Prompt.ask(MESSAGES[lang]["prompt_charset"], default=charset)
            max_length = int(Prompt.ask(MESSAGES[lang]["prompt_maxlen"], default=str(max_length)))
            dryrun = Confirm.ask(MESSAGES[lang]["prompt_dryrun"], default=False)
        elif choice == "3":
            wordlist = load_wordlist(wordlist_path, lang)
            preview_wordlist(wordlist, lang)
        elif choice == "1":
            console.print(f"[yellow]{MESSAGES[lang]['msg_enc_detect']}[/yellow]")
            typ = detect_encryption(zipfile_path, lang)
            console.print(f"[blue]{MESSAGES[lang]['msg_enc_type']}:[/blue] [bold]{typ}[/bold]")
            wordlist = load_wordlist(wordlist_path, lang)
            preview_wordlist(wordlist, lang)
            eta = len(wordlist) * 0.05
            console.print(f"[yellow]{MESSAGES[lang]['msg_eta']}:[/yellow] {int(eta//60)}min {int(eta%60)}s")
            if not Confirm.ask(MESSAGES[lang]['msg_start']):
                continue
            found, log, dauer = crack_dictionary(zipfile_path, wordlist, lang, dryrun=dryrun, resume=resume)
            if found:
                console.print(f"{MESSAGES[lang]['msg_found']} {found}[/green]")
            else:
                console.print(MESSAGES[lang]['msg_notfound'])
            logfile, exportfile = save_log(log, found, dauer, "dictionary", lang)
            console.print(f"{MESSAGES[lang]['msg_log_saved']} {logfile} {MESSAGES[lang]['msg_export_saved']} {exportfile}[/cyan]")
        elif choice == "2":
            charset_str = f"[magenta]{charset}[/magenta]"
            console.print(f"{MESSAGES[lang]['msg_charset_info']}: {charset_str}, {MESSAGES[lang]['msg_maxlen_info']}: [magenta]{max_length}[/magenta]")
            if not Confirm.ask(MESSAGES[lang]['msg_start_warn']):
                continue
            found, log, dauer = crack_bruteforce(zipfile_path, charset, max_length, lang, dryrun=dryrun, resume=resume)
            if found:
                console.print(f"{MESSAGES[lang]['msg_found']} {found}[/green]")
            else:
                console.print(MESSAGES[lang]['msg_notfound'])
            logfile, exportfile = save_log(log, found, dauer, "bruteforce", lang)
            console.print(f"{MESSAGES[lang]['msg_log_saved']} {logfile} {MESSAGES[lang]['msg_export_saved']} {exportfile}[/cyan]")

if __name__ == "__main__":
    main()
