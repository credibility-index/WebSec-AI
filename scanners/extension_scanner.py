import re, os, zipfile, json, base64, tempfile
from mnemonic import Mnemonic
from pathlib import Path

class WebSecAIScanner:
    def __init__(self):
        self.mnemo = Mnemonic("english")
        self.wordlist = set(self.mnemo.wordlist)
        self.bip39_patterns = [r'bip39\..*mnemonic', r'atob\.*mnemonic', r'eval\(base64']
        self.drain_patterns = [r'eth_sendTransaction', r'web3\.*send', r'uniswap\.*swap', r'wallet_drain']

    def scan_crx(self, file_path):
        results = {'critical': 0, 'high': 0, 'threats': []}
        with tempfile.TemporaryDirectory() as temp_dir:
            with zipfile.ZipFile(file_path, 'r') as zip_ref:
                zip_ref.extractall(temp_dir)
            for js_file in Path(temp_dir).rglob('*.js'):
                content = js_file.read_text(errors='ignore')
                
                # BIP39 sequence (12+ words)
                words = re.findall(r'\b\w+\b', content.lower())
                bip_words = [w for w in words if w in self.wordlist]
                if len(bip_words) >= 12:
                    results['critical'] += 1
                    results['threats'].append(f"🚨 BIP39: {js_file.name} ({bip_words[:3]}...)")
                
                # Drain signatures
                for pat in self.bip39_patterns + self.drain_patterns:
                    if re.search(pat, content):
                        level = 'critical' if any(crit in pat for crit in ['sendTransaction', 'wallet_drain']) else 'high'
                        results[level] += 1
                        results['threats'].append(f"{level.upper()}: {pat} → {js_file.name}")
        
        return results

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description="WebSecAI CRX Drainer Scanner")
    parser.add_argument('file', help="Path to .crx file")
    args = parser.parse_args()
    
    scanner = WebSecAIScanner()
    results = scanner.scan_crx(args.file)
    print(json.dumps(results, indent=2))

