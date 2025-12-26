import re, os, zipfile, json, base64
from mnemonic import Mnemonic  # pip install mnemonic
from pathlib import Path
from collections import Counter

class WebSecAIScanner:
    def __init__(self):
        self.mnemo = Mnemonic("english")
        self.wordlist = set(self.mnemo.wordlist)
        self.bip39_patterns = [
            r'bip39.mnemonicToSeed', r'bip39.mnemonicToEntropy', r'pbkdf2.*mnemonic',
            r'atob.*mnemonic', r'eval(base64', r'seedToMnemonic'
        ]
        self.chain_patterns = [
            r'eth_sendTransaction', r'web3.*send', r'contract.approve', r'uniswap.*swap',
            r'wallet_drain', r'/drainer/'
        ]

    def scan_crx(self, file_path):
        results = {'critical': 0, 'high': 0, 'medium': 0, 'threats': []}
        with tempfile.TemporaryDirectory() as temp_dir:
            with zipfile.ZipFile(file_path, 'r') as zip_ref:
                zip_ref.extractall(temp_dir)
            for js_file in Path(temp_dir).rglob('*.js'):
                content = js_file.read_text(errors='ignore')
                words = re.findall(r'\bw+\b', content.lower())
                bip_words = [w for w in words if w in self.wordlist]
                if len(bip_words) >= 12:
                    results['critical'] += 1
                    results['threats'].append(f"BIP39 sequence in {js_file}: {bip_words[:5]}...")
                for pat in self.bip39_patterns + self.chain_patterns:
                    if re.search(pat, content):
                        level = 'critical' if 'sendTransaction' in pat else 'high'
                        results[level] += 1
                        results['threats'].append(f"{level.upper()}: {pat} in {js_file}")
        return results

# CLI: python scanner.py suspicious.crx
if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('file')
    args = parser.parse_args()
    scanner = WebSecAIScanner()
    print(json.dumps(scanner.scan_crx(args.file), indent=2))
