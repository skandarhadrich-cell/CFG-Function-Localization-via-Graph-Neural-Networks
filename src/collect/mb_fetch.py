import requests
import os
import subprocess
import tempfile
from tqdm import tqdm
from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(__file__), "..", "..", ".env"))

OUTPUT_DIR = os.path.expanduser("~/cfg-gnn/data/raw")
API_KEY = os.environ.get("MB_API_KEY", "")
HEADERS = {"Auth-Key": API_KEY}
LIMIT = 25

QUERIES = [
    ("AgentTesla",  "keylogger"),
    ("Keylogger",   "keylogger"),
    ("njRAT",       "injection"),
    ("RemcosRAT",   "injection"),
    ("Zeus",        "antidebug"),
]

def fetch_by_tag(tag, family_dir, limit=25):
    os.makedirs(family_dir, exist_ok=True)
    print(f"\n[*] Querying MalwareBazaar for tag: {tag}")
    resp = requests.post(
        "https://mb-api.abuse.ch/api/v1/",
        headers=HEADERS,
        data={"query": "get_taginfo", "tag": tag, "limit": limit}
    )
    data = resp.json()
    if data.get("query_status") != "ok":
        print(f"[-] No results for tag: {tag} — status: {data.get('query_status')}")
        return 0

    samples = data.get("data", [])
    print(f"[+] Found {len(samples)} samples")
    downloaded = 0

    for sample in tqdm(samples):
        sha256 = sample.get("sha256_hash")
        file_type = sample.get("file_type", "")

        if "exe" not in file_type.lower() and "dll" not in file_type.lower():
            continue

        out_path = os.path.join(family_dir, sha256)
        if os.path.exists(out_path):
            downloaded += 1
            continue

        dl = requests.post(
            "https://mb-api.abuse.ch/api/v1/",
            headers=HEADERS,
            data={"query": "get_file", "sha256_hash": sha256}
        )
        if dl.status_code != 200:
            continue

        try:
            with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
                tmp.write(dl.content)
                tmp_path = tmp.name

            result = subprocess.run(
                ["7z", "e", f"-p infected", tmp_path, f"-o{family_dir}", "-y"],
                capture_output=True, text=True
            )

            # rename extracted file to sha256
            for f in os.listdir(family_dir):
                fpath = os.path.join(family_dir, f)
                if os.path.isfile(fpath) and f != sha256:
                    os.rename(fpath, out_path)
                    break

            os.unlink(tmp_path)
            downloaded += 1
        except Exception as e:
            print(f"[-] Failed {sha256}: {e}")

    return downloaded

if __name__ == "__main__":
    if not API_KEY:
        print("[-] MB_API_KEY not set")
        exit(1)
    total = 0
    for tag, family in QUERIES:
        family_dir = os.path.join(OUTPUT_DIR, family)
        total += fetch_by_tag(tag, family_dir, LIMIT)
    print(f"\n[+] Total downloaded: {total}")
