"""
WebSecAI Extension Scanner
Анализ .crx/.zip расширений на наличие крипто-дрейнеров и утечек SEED-фраз.
"""

import re
import zipfile
import tempfile
import logging
from pathlib import Path

# Попробуем импортировать mnemonic, но если нет - сделаем fallback
try:
    from mnemonic import Mnemonic
    HAS_MNEMONIC = True
except ImportError:
    HAS_MNEMONIC = False

# Сигнатуры угроз
DRAIN_PATTERNS = {
    "CRITICAL": [
        r'eth_sendTransaction', 
        r'wallet_drain', 
        r'privateKey', 
        r'mnemonic.*=.*".+"'
    ],
    "HIGH": [
        r'web3\..*send', 
        r'uniswap\..*swap', 
        r'bip39\..*mnemonic', 
        r'eval\(base64'
    ]
}

def scan_crx_file(file_obj) -> dict:
    """
    Сканирует загруженный файл (BytesIO или путь) на угрозы.
    Возвращает словарь с результатами.
    """
    results = {'critical': 0, 'high': 0, 'threats': []}
    
    # Словарик слов BIP39 (если либа есть)
    wordlist = set()
    if HAS_MNEMONIC:
        try:
            mnemo = Mnemonic("english")
            wordlist = set(mnemo.wordlist)
        except: pass

    try:
        with tempfile.TemporaryDirectory() as temp_dir:
            # Распаковываем (поддерживает и zip, и crx если это zip-формат)
            with zipfile.ZipFile(file_obj, 'r') as zip_ref:
                zip_ref.extractall(temp_dir)
            
            # Проход по всем JS файлам
            for js_file in Path(temp_dir).rglob('*.js'):
                try:
                    content = js_file.read_text(errors='ignore')
                    
                    # 1. Поиск BIP39 (12 слов подряд) - только если есть либа
                    if wordlist:
                        words = re.findall(r'\b[a-z]{3,}\b', content.lower())
                        # Ищем последовательности
                        consecutive_bip = 0
                        for w in words:
                            if w in wordlist:
                                consecutive_bip += 1
                            else:
                                consecutive_bip = 0
                            
                            if consecutive_bip >= 12:
                                results['critical'] += 1
                                results['threats'].append(f"🚨 Possible SEED phrase leak in {js_file.name}")
                                break

                    # 2. Поиск сигнатур (Regex)
                    for severity, patterns in DRAIN_PATTERNS.items():
                        for pat in patterns:
                            if re.search(pat, content, re.IGNORECASE):
                                level = severity.lower()
                                results[level] += 1
                                results['threats'].append(f"{severity}: Found '{pat}' in {js_file.name}")
                                
                except Exception as e:
                    logging.warning(f"Error scanning {js_file}: {e}")

    except zipfile.BadZipFile:
        results['threats'].append("❌ Error: Invalid CRX/ZIP file format")
    except Exception as e:
        results['threats'].append(f"❌ Scan Error: {str(e)}")
        
    return results

if __name__ == '__main__':
    print("This module is part of WebSecAI.")
