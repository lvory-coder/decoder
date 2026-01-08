import re
import base64
import string
import os
import struct
import zipfile
import tempfile
from collections import Counter, defaultdict
from typing import Dict, List, Optional, Tuple, Any, BinaryIO, Set
import binascii
import urllib.parse
import itertools
import math
import json
import random

class AdvancedCTFDecoder:
    def __init__(self):
        self.common_words = {'the', 'and', 'for', 'are', 'but', 'not', 'you', 'all', 'can', 'was',
                            'flag', 'ctf', 'crypto', 'find', 'secret', 'key', 'hidden', 'data',
                            'that', 'with', 'have', 'this', 'from', 'they', 'would', 'there',
                            'hello', 'world', 'test', 'message', 'password', 'admin', 'user'}
        
        self.extended_words = self.common_words.union({
            'when', 'your', 'said', 'each', 'which', 'she', 'their', 'will', 'other', 'about',
            'out', 'many', 'then', 'them', 'these', 'some', 'her', 'would', 'make', 'like',
            'him', 'into', 'time', 'has', 'look', 'two', 'more', 'write', 'go', 'see',
            'number', 'no', 'way', 'could', 'people', 'my', 'than', 'first', 'water', 'been',
            'call', 'who', 'oil', 'its', 'now', 'find', 'long', 'down', 'day', 'did', 'get',
            'come', 'made', 'may', 'part', 'over', 'new', 'sound', 'take', 'only', 'little',
            'work', 'know', 'place', 'year', 'live', 'me', 'back', 'give', 'most', 'very',
            'after', 'thing', 'our', 'just', 'name', 'good', 'sentence', 'man', 'think', 'say'
        })
        
        self.cipher_types = {
            '1': 'base64',
            '2': 'hex',
            '3': 'binary',
            '4': 'caesar/rot',
            '5': 'atbash',
            '6': 'url encoding',
            '7': 'morse code',
            '8': 'rail fence',
            '9': 'xor',
            '10': 'reverse',
            '11': 'base32',
            '12': 'base16',
            '13': 'affine cipher',
            '14': 'bacon cipher',
            '15': 'vigenere (улучшенный)',
            '16': 'substitution (частотный анализ)',
            '17': 'RC4',
            '18': 'playfair',
            '19': 'columnar transposition',
            '20': 'autokey',
            '21': 'омофонический шифр',
            '22': 'великий шифр (Гронсфельд)',
            '23': 'портный шифр (Porta)',
            '24': 'шифр Бофора',
            '0': 'автоопределение + поиск флага'
        }
        
        self.english_freq = {
            'e': 12.02, 't': 9.10, 'a': 8.12, 'o': 7.68, 'i': 7.31,
            'n': 6.95, 's': 6.28, 'r': 6.02, 'h': 5.92, 'd': 4.32,
            'l': 3.98, 'u': 2.88, 'c': 2.71, 'm': 2.61, 'f': 2.30,
            'y': 2.11, 'w': 2.09, 'g': 2.03, 'p': 1.82, 'b': 1.49,
            'v': 1.11, 'k': 0.69, 'x': 0.17, 'q': 0.11, 'j': 0.10,
            'z': 0.07
        }
        
        self.english_freq_upper = {k.upper(): v for k, v in self.english_freq.items()}
        
        self.key_database = {
            'common_words': [
                'password', 'secret', 'key', 'admin', '123456', 'qwerty', 'letmein',
                'welcome', 'monkey', 'dragon', 'sunshine', 'master', 'hello', 'freedom',
                'whatever', 'qazwsx', 'trustno1', 'superman', 'iloveyou', 'starwars'
            ],
            'ctf_keywords': [
                'flag', 'ctf', 'hack', 'crypto', 'security', 'xor', 'key', 'secret',
                'password', 'admin', 'root', 'backdoor', 'exploit', 'shell', 'payload',
                'vulnerability', 'patch', 'update', 'bug', 'fix'
            ],
            'short_keys': [
                'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
                'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
                'aa', 'ab', 'ac', 'ad', 'ae', 'af', 'ag', 'ah', 'ai', 'aj',
                'ba', 'bb', 'bc', 'bd', 'be', 'bf', 'bg', 'bh', 'bi', 'bj'
            ],
            'numeric_keys': [
                '1', '2', '3', '4', '5', '6', '7', '8', '9', '0',
                '11', '22', '33', '44', '55', '66', '77', '88', '99', '00',
                '12', '23', '34', '45', '56', '67', '78', '89', '90',
                '123', '234', '345', '456', '567', '678', '789', '890',
                '1234', '2345', '3456', '4567', '5678', '6789', '7890',
                '1111', '2222', '3333', '4444', '5555', '6666', '7777', '8888', '9999', '0000'
            ],
            'vigenere_keys': [
                'KEY', 'SECRET', 'PASSWORD', 'CRYPTO', 'FLAG', 'CTF', 'HACK',
                'ABC', 'TEST', 'WORD', 'CODE', 'CIPHER', 'ENCRYPT', 'DECRYPT',
                'SECURITY', 'PRIVACY', 'MESSAGE', 'TEXT', 'DATA', 'INFO'
            ],
            'gronsfeld_keys': [
                '12345', '54321', '11111', '22222', '33333', '44444', '55555',
                '1234', '4321', '2023', '2024', '1337', '2600', '31415', '27182',
                '123', '321', '456', '654', '789', '987', '000', '999', '8080'
            ],
            'porta_keys': [
                'KEY', 'SECRET', 'PORTACIPHER', 'CRYPTO', 'ENCRYPT', 'DECODE',
                'ABCD', 'WXYZ', 'TEST', 'PASS', 'WORD', 'CODE', 'DATA', 'TEXT'
            ],
            'beaufort_keys': [
                'KEY', 'SECRET', 'BEAUFORT', 'CIPHER', 'DECODE', 'ENCRYPT',
                'TEST', 'ABCD', 'WXYZ', 'PASS', 'WORD', 'CODE', 'TEXT'
            ],
            'autokey_keys': [
                'KEY', 'SECRET', 'AUTOKEY', 'CIPHER', 'CRYPTO', 'TEST',
                'ABCD', 'WXYZ', 'PASS', 'WORD', 'CODE', 'TEXT', 'DATA'
            ]
        }
        
        self.ctf_mode = False
        self.flag_prefix = ""
        self.known_key = None
        
        self.possible_flag_formats = [
            r'flag\{[^}]+\}',
            r'FLAG\{[^}]+\}',
            r'ctf\{[^}]+\}',
            r'CTF\{[^}]+\}',
            r'inctf\{[^}]+\}',
            r'pico\{[^}]+\}',
            r'PICO\{[^}]+\}',
            r'hacktm\{[^}]+\}',
            r'corctf\{[^}]+\}',
            r'sdctf\{[^}]+\}',
            r'HTB\{[^}]+\}',
            r'THC\{[^}]+\}'
        ]
        
        self.english_letters = string.ascii_letters
        self.basic_symbols = ' .,!?;:\'"-()[]{}@#$%^&*+=_|<>/~`'
        self.allowed_chars = self.english_letters + self.basic_symbols
    
    def show_banner(self):
        banner = """
        ╔══════════════════════════════════════════════════════════╗
        ║             ADVANCED CTF DECODER PRO PLUS               ║
        ║      (перебор ключей для всех шифров)                   ║
        ╚══════════════════════════════════════════════════════════╝
        """
        print(banner)
    
    def setup_ctf_mode(self):
        print("\n" + "=" * 60)
        print("НАСТРОЙКА CTF РЕЖИМА")
        print("=" * 60)
        
        ctf_choice = input("Включить CTF режим (поиск флага)? (y/n): ").strip().lower()
        
        if ctf_choice in ['y', 'yes', 'д', 'да']:
            self.ctf_mode = True
            print("\nВыберите формат флага:")
            print("  1. Использовать стандартные форматы")
            print("  2. Ввести свою форму флага")
            
            format_choice = input("Ваш выбор (1-2): ").strip()
            
            if format_choice == '1':
                print("\nДоступные форматы флагов:")
                for i, fmt in enumerate(self.possible_flag_formats, 1):
                    flag_example = self._format_to_example(fmt)
                    print(f"  {i:2d}. {flag_example}")
                
                fmt_num = input("\nВыберите номер формата (1-12) или Enter для flag{}: ").strip()
                if fmt_num and fmt_num.isdigit():
                    idx = int(fmt_num) - 1
                    if 0 <= idx < len(self.possible_flag_formats):
                        self.flag_prefix = self.possible_flag_formats[idx]
                        print(f"Выбран формат: {self._format_to_example(self.flag_prefix)}")
                    else:
                        self.flag_prefix = r'flag\{[^}]+\}'
                        print("Используем стандартный формат: flag{...}")
                else:
                    self.flag_prefix = r'flag\{[^}]+\}'
                    print("Используем стандартный формат: flag{...}")
            
            elif format_choice == '2':
                print("\nВведите форму флага (например: flag{...}, CTF{...}):")
                print("Используйте {...} для обозначения содержимого флага")
                custom_flag = input("Ваша форма флага: ").strip()
                
                if custom_flag:
                    try:
                        self.flag_prefix = self._custom_flag_to_regex(custom_flag)
                        print(f"Форма флага установлена: {custom_flag}")
                    except:
                        self.flag_prefix = r'flag\{[^}]+\}'
                        print("Ошибка, используем стандартный формат: flag{...}")
                else:
                    self.flag_prefix = r'flag\{[^}]+\}'
                    print("Используем стандартный формат: flag{...}")
            
            else:
                self.flag_prefix = r'flag\{[^}]+\}'
                print("Используем стандартный формат: flag{...}")
        else:
            self.ctf_mode = False
            print("CTF режим отключен")
    
    def _custom_flag_to_regex(self, flag_format: str) -> str:
        if '{' in flag_format and '}' in flag_format:
            parts = flag_format.split('{', 1)
            if len(parts) == 2:
                prefix = parts[0]
                suffix = parts[1]
                if '}' in suffix:
                    return re.escape(prefix) + r'\{[^}]+' + re.escape(suffix[suffix.index('}'):])
        return r'flag\{[^}]+\}'
    
    def _format_to_example(self, fmt: str) -> str:
        if fmt == r'flag\{[^}]+\}':
            return "flag{something_here}"
        elif fmt == r'FLAG\{[^}]+\}':
            return "FLAG{SOMETHING_HERE}"
        elif fmt == r'ctf\{[^}]+\}':
            return "ctf{something_here}"
        elif fmt == r'CTF\{[^}]+\}':
            return "CTF{SOMETHING_HERE}"
        else:
            match = re.match(r'([A-Za-z_]+)\\{[^}]+\\}', fmt)
            if match:
                return f"{match.group(1)}{{example}}"
            return fmt
    
    def show_menu(self):
        print("\n" + "=" * 60)
        print("ДОСТУПНЫЕ ТИПЫ ШИФРОВ / КОДИРОВОК:")
        print("=" * 60)
        
        for key, value in sorted(self.cipher_types.items()):
            print(f"  [{key}] {value}")
        
        print("\n" + "=" * 60)
    
    def get_user_input(self):
        print("\n" + "=" * 60)
        print("ВВОД ЗАКОДИРОВАННОЙ СТРОКИ:")
        print("=" * 60)
        
        print("Введите текст (для окончания ввода нажмите Enter дважды):")
        lines = []
        empty_count = 0
        
        while True:
            try:
                line = input()
                if line == "":
                    empty_count += 1
                    if empty_count >= 2:
                        break
                else:
                    empty_count = 0
                    lines.append(line)
            except (EOFError, KeyboardInterrupt):
                break
        
        text = '\n'.join(lines)
        
        if not text.strip():
            print("Ошибка: введена пустая строка!")
            return None
        
        return text
    
    def analyze_and_suggest(self, text: str) -> List[str]:
        suggestions = []
        
        if isinstance(text, bytes):
            text_str = text.decode('ascii', errors='ignore')
        else:
            text_str = str(text)
        
        clean_text = re.sub(r'\s+', '', text_str)
        
        if re.match(r'^[A-Za-z0-9+/]*={0,2}$', clean_text):
            suggestions.append("base64")
        
        if re.match(r'^[0-9a-fA-F]+$', clean_text) and len(clean_text) % 2 == 0:
            suggestions.append("hex")
        
        binary_clean = text_str.replace(' ', '').replace('\n', '')
        if re.match(r'^[01]+$', binary_clean):
            suggestions.append("binary")
        
        letters_only = re.sub(r'[^A-Za-z]', '', text_str)
        if len(letters_only) > 10:
            letter_ratio = len(letters_only) / len(text_str.replace('\n', '').replace(' ', ''))
            if letter_ratio > 0.7:
                suggestions.append("caesar/atbash/vigenere")
        
        if '%' in text_str and re.search(r'%[0-9A-Fa-f]{2}', text_str):
            suggestions.append("url encoding")
        
        hex_match = re.match(r'^[0-9a-fA-F]+$', clean_text)
        if hex_match and len(clean_text) % 2 == 0 and len(clean_text) >= 20:
            suggestions.append("xor (возможно)")
        
        if re.match(r'^[A-Z2-7]+=*$', clean_text):
            suggestions.append("base32")
        
        return suggestions
    
    def check_for_flag(self, text: str) -> List[str]:
        flags = []
        
        if not self.ctf_mode or not self.flag_prefix:
            return flags
        
        try:
            found = re.findall(self.flag_prefix, text)
            flags.extend(found)
        except:
            pass
        
        if not flags:
            for fmt in self.possible_flag_formats:
                try:
                    found = re.findall(fmt, text)
                    flags.extend(found)
                except:
                    continue
        
        return list(set(flags))
    
    def _is_readable(self, text: str, threshold: float = 0.3) -> bool:
        if len(text) < 3:
            return False
        
        if self.ctf_mode and self.check_for_flag(text):
            return True
        
        words = re.findall(r'[A-Za-z]{2,}', text)
        if not words:
            return False
        
        english_words = sum(1 for w in words if w.lower() in self.common_words)
        ratio = english_words / len(words)
        
        printable = sum(1 for c in text if 32 <= ord(c) <= 126 or c in '\n\r\t')
        printable_ratio = printable / len(text)
        
        return ratio > threshold or printable_ratio > 0.7
    
    def _readability_score(self, text: str) -> float:
        if len(text) < 5:
            return 0.0
        
        words = re.findall(r'[A-Za-z]{2,}', text)
        if not words:
            return 0.0
        
        english_words = sum(1 for w in words if w.lower() in self.common_words)
        score = (english_words / max(1, len(words))) * 0.7
        
        space_ratio = text.count(' ') / len(text)
        score += min(space_ratio, 0.2) * 2
        
        if any(c in text for c in '.!?,;:'):
            score += 0.1
        
        return score
    
    def decode_caesar(self, text: str) -> List[Dict]:
        results = []
        
        letters = ''.join(c for c in text if c.isalpha())
        if len(letters) < 5:
            return results
        
        print(f"\n🔐 ПЕРЕБОР ШИФРА ЦЕЗАРЯ (ROT0-25):")
        
        for shift in range(26):
            decrypted = []
            for char in text:
                if char.isupper():
                    decrypted.append(chr((ord(char) - ord('A') - shift) % 26 + ord('A')))
                elif char.islower():
                    decrypted.append(chr((ord(char) - ord('a') - shift) % 26 + ord('a')))
                else:
                    decrypted.append(char)
            
            result_str = ''.join(decrypted)
            
            if self._is_readable(result_str):
                results.append({
                    'method': f'caesar_rot{shift}',
                    'result': result_str,
                    'success': True,
                    'key': f'shift={shift}',
                    'score': self._readability_score(result_str)
                })
        
        results.sort(key=lambda x: x.get('score', 0), reverse=True)
        
        if results:
            print(f"   Найдено {len(results)} читаемых вариантов")
            best = results[0]
            print(f"   Лучший сдвиг: ROT{best['key'].split('=')[1]} (оценка: {best['score']:.3f})")
        
        return results[:10]
    
    def decode_affine(self, text: str) -> List[Dict]:
        results = []
        
        letters = ''.join(c for c in text if c.isalpha())
        if len(letters) < 10:
            return results
        
        print(f"\n🔐 ПЕРЕБОР АФФИННОГО ШИФРА:")
        print("   Проверяем все допустимые значения a и b...")
        
        valid_a_values = [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25]
        tested = 0
        found = 0
        
        for a in valid_a_values:
            a_inv = None
            for i in range(26):
                if (a * i) % 26 == 1:
                    a_inv = i
                    break
            
            if a_inv is None:
                continue
            
            for b in range(26):
                tested += 1
                decrypted = []
                for char in text:
                    if char.isupper():
                        x = ord(char) - ord('A')
                        y = (a_inv * (x - b)) % 26
                        decrypted.append(chr(y + ord('A')))
                    elif char.islower():
                        x = ord(char) - ord('a')
                        y = (a_inv * (x - b)) % 26
                        decrypted.append(chr(y + ord('a')))
                    else:
                        decrypted.append(char)
                
                result_str = ''.join(decrypted)
                if self._is_readable(result_str):
                    found += 1
                    results.append({
                        'method': f'affine_a{a}_b{b}',
                        'result': result_str,
                        'success': True,
                        'key': f'a={a}, b={b}',
                        'score': self._readability_score(result_str)
                    })
        
        results.sort(key=lambda x: x.get('score', 0), reverse=True)
        
        print(f"   Протестировано {tested} комбинаций, найдено {found} читаемых")
        
        if results:
            best = results[0]
            print(f"   Лучший ключ: {best['key']} (оценка: {best['score']:.3f})")
        
        return results[:10]
    
    def decode_xor_bruteforce(self, text: str) -> List[Dict]:
        results = []
        
        data = None
        
        hex_chars = re.findall(r'[0-9a-fA-F]+', text if isinstance(text, str) else text.decode('ascii', errors='ignore'))
        if hex_chars:
            hex_string = ''.join(hex_chars)
            try:
                data = bytes.fromhex(hex_string)
            except:
                pass
        
        if not data:
            if isinstance(text, str):
                try:
                    data = text.encode('utf-8')
                except:
                    return results
            else:
                data = text
        
        if len(data) == 0:
            return results
        
        print(f"\n🔐 ПЕРЕБОР XOR ({len(data)} байт):")
        print("   1. Одиночные байты (0-255)")
        print("   2. Распространенные слова")
        print("   3. CTF-ключевые слова")
        print("   4. Повторяющиеся байты")
        
        single_byte_results = []
        for key in range(256):
            try:
                decrypted = bytes(b ^ key for b in data)
                decoded = decrypted.decode('utf-8', errors='ignore')
                
                if self._is_readable(decoded):
                    score = self._readability_score(decoded)
                    single_byte_results.append({
                        'method': f'xor_single_byte_{key:02x}({key})',
                        'result': decoded,
                        'success': True,
                        'key': f'{key:02x}',
                        'score': score
                    })
                    
                    if len(single_byte_results) >= 10:
                        break
            except:
                continue
        
        single_byte_results.sort(key=lambda x: x.get('score', 0), reverse=True)
        results.extend(single_byte_results[:5])
        
        if single_byte_results:
            best = single_byte_results[0]
            print(f"   Лучший одиночный байт: 0x{best['key']} (оценка: {best['score']:.3f})")
        
        popular_keys = [
            b'password', b'secret', b'key', b'admin', b'12345678',
            b'qwertyui', b'letmein', b'welcome', b'password123',
            b'flag', b'ctf', b'crypto', b'hack', b'security'
        ]
        
        multi_byte_results = []
        for key in popular_keys:
            try:
                decrypted = self._xor_with_key(data, key)
                decoded = decrypted.decode('utf-8', errors='ignore')
                
                if self._is_readable(decoded):
                    score = self._readability_score(decoded)
                    multi_byte_results.append({
                        'method': f'xor_multi_byte_{key.decode("ascii", errors="ignore")}',
                        'result': decoded,
                        'success': True,
                        'key': key.hex(),
                        'score': score
                    })
            except:
                continue
        
        multi_byte_results.sort(key=lambda x: x.get('score', 0), reverse=True)
        results.extend(multi_byte_results[:5])
        
        if multi_byte_results:
            best = multi_byte_results[0]
            print(f"   Лучший многобайтовый ключ: {best['key']} (оценка: {best['score']:.3f})")
        
        unique_results = []
        seen_texts = set()
        
        for result in results:
            if result['result'] not in seen_texts:
                seen_texts.add(result['result'])
                unique_results.append(result)
        
        unique_results.sort(key=lambda x: x.get('score', 0), reverse=True)
        
        return unique_results[:10]
    
    def _xor_with_key(self, data: bytes, key: bytes) -> bytes:
        result = bytearray()
        key_len = len(key)
        
        for i, byte in enumerate(data):
            result.append(byte ^ key[i % key_len])
        
        return bytes(result)
    
    def decode_vigenere(self, text: str) -> List[Dict]:
        results = []
        
        letters_only = re.sub(r'[^A-Za-z]', '', text)
        if len(letters_only) < 30:
            print("Недостаточно букв для анализа Виженера (нужно минимум 30)")
            return results
        
        text_upper = letters_only.upper()
        
        print(f"\n🔐 ПЕРЕБОР ШИФРА ВИЖЕНЕРА:")
        
        key_length = self._kasiski_examination(text_upper)
        if key_length > 0:
            print(f"   Предполагаемая длина ключа (анализ Казиски): {key_length}")
        
        all_keys = []
        
        for length in range(1, 9):
            if length <= 3:
                for key in self.key_database['short_keys']:
                    if len(key) == length:
                        all_keys.append(key.upper())
            
            for key in self.key_database['vigenere_keys']:
                if len(key) == length or (key_length > 0 and abs(len(key) - key_length) <= 2):
                    all_keys.append(key.upper())
            
            if self.ctf_mode:
                for key in self.key_database['ctf_keywords']:
                    if len(key) == length:
                        all_keys.append(key.upper())
        
        all_keys = list(set(all_keys))[:100]
        
        print(f"   Перебираем {len(all_keys)} ключей...")
        
        tested = 0
        for key in all_keys:
            tested += 1
            decrypted = self._vigenere_decrypt_improved(text, key)
            
            if self._is_readable(decrypted):
                score = self._readability_score(decrypted)
                results.append({
                    'method': f'vigenere_key_{key}',
                    'result': decrypted,
                    'success': True,
                    'key': key,
                    'score': score,
                    'key_length': len(key)
                })
        
        if key_length > 0:
            print(f"   Генерация ключей на основе анализа (длина: {key_length})...")
            auto_keys = self._generate_vigenere_keys_from_analysis(text_upper, key_length)
            
            for key in auto_keys[:50]:
                decrypted = self._vigenere_decrypt_improved(text, key)
                
                if self._is_readable(decrypted):
                    score = self._readability_score(decrypted)
                    results.append({
                        'method': f'vigenere_auto_{key}',
                        'result': decrypted,
                        'success': True,
                        'key': key,
                        'score': score,
                        'key_length': len(key)
                    })
        
        unique_results = []
        seen_texts = set()
        
        for result in results:
            if result['result'] not in seen_texts:
                seen_texts.add(result['result'])
                unique_results.append(result)
        
        unique_results.sort(key=lambda x: x.get('score', 0), reverse=True)
        
        print(f"   Протестировано {tested} ключей, найдено {len(unique_results)} читаемых вариантов")
        
        if unique_results:
            best = unique_results[0]
            print(f"   Лучший ключ: '{best['key']}' (оценка: {best['score']:.3f})")
        
        return unique_results[:10]
    
    def _kasiski_examination(self, text: str, max_key_length: int = 20) -> int:
        sequences = {}
        
        for seq_len in range(3, 6):
            for i in range(len(text) - seq_len + 1):
                sequence = text[i:i+seq_len]
                if sequence.isalpha():
                    if sequence in sequences:
                        sequences[sequence].append(i)
                    else:
                        sequences[sequence] = [i]
        
        repeating_seqs = {seq: positions for seq, positions in sequences.items() 
                         if len(positions) >= 2}
        
        if not repeating_seqs:
            return 0
        
        distances = []
        for positions in repeating_seqs.values():
            for i in range(len(positions)):
                for j in range(i+1, len(positions)):
                    distances.append(positions[j] - positions[i])
        
        if not distances:
            return 0
        
        possible_lengths = Counter()
        
        for i in range(len(distances)):
            for j in range(i+1, len(distances)):
                gcd = math.gcd(distances[i], distances[j])
                if 2 <= gcd <= max_key_length:
                    possible_lengths[gcd] += 1
        
        if possible_lengths:
            return possible_lengths.most_common(1)[0][0]
        
        return 0
    
    def _generate_vigenere_keys_from_analysis(self, text: str, key_length: int) -> List[str]:
        keys = []
        
        groups = [''] * key_length
        for i, char in enumerate(text):
            groups[i % key_length] += char
        
        probable_letters = []
        for group in groups:
            if len(group) >= 10:
                freq = Counter(group)
                most_common = [letter for letter, _ in freq.most_common(3)]
                probable_letters.append(most_common)
            else:
                probable_letters.append(['A', 'B', 'C'])
        
        if len(probable_letters) == key_length:
            combinations = list(itertools.product(*probable_letters))
            
            for combo in combinations[:100]:
                keys.append(''.join(combo))
        
        return keys
    
    def _vigenere_decrypt_improved(self, text: str, key: str) -> str:
        result = []
        key = key.upper()
        key_len = len(key)
        key_index = 0
        
        for char in text:
            if char.isupper():
                shift = ord(key[key_index % key_len]) - ord('A')
                decrypted = chr((ord(char) - ord('A') - shift) % 26 + ord('A'))
                result.append(decrypted)
                key_index += 1
            elif char.islower():
                shift = ord(key[key_index % key_len].upper()) - ord('A')
                decrypted = chr((ord(char) - ord('a') - shift) % 26 + ord('a'))
                result.append(decrypted)
                key_index += 1
            else:
                result.append(char)
        
        return ''.join(result)
    
    def decode_great_cipher(self, text: str) -> List[Dict]:
        results = []
        
        letters_only = re.sub(r'[^A-Za-z]', '', text)
        if len(letters_only) < 20:
            print("Недостаточно букв для анализа (нужно минимум 20)")
            return results
        
        text_upper = letters_only.upper()
        
        print(f"\n🔐 ПЕРЕБОР ШИФРА ГРОНСФЕЛЬДА:")
        
        all_keys = []
        
        for key in self.key_database['gronsfeld_keys']:
            all_keys.append(key)
        
        ctf_numeric_keys = [
            '1337', '2600', '31337', '65535', '32767', '2147483647',
            '1024', '2048', '4096', '8192', '1234', '4321'
        ]
        
        for key in ctf_numeric_keys:
            all_keys.append(key)
        
        for length in range(1, 7):
            for digit in '0123456789':
                all_keys.append(digit * length)
            
            if length >= 3:
                for start in range(0, 10 - length + 1):
                    seq = ''.join(str((start + i) % 10) for i in range(length))
                    all_keys.append(seq)
                    all_keys.append(seq[::-1])
        
        all_keys = list(set(all_keys))[:200]
        
        print(f"   Перебираем {len(all_keys)} цифровых ключей...")
        
        tested = 0
        found = 0
        for key in all_keys:
            tested += 1
            decrypted = self._gronsfeld_decrypt(text, key)
            
            if self._is_readable(decrypted):
                found += 1
                score = self._readability_score(decrypted)
                results.append({
                    'method': f'gronsfeld_key_{key}',
                    'result': decrypted,
                    'success': True,
                    'key': key,
                    'score': score,
                    'key_length': len(key)
                })
        
        print(f"   Также пробуем ключи как буквенные (A=0, B=1...)")
        for key in all_keys[:50]:
            if key.isdigit():
                letter_key = ''.join(chr(int(digit) + ord('A')) for digit in key if digit.isdigit())
                if letter_key:
                    decrypted = self._vigenere_decrypt_improved(text, letter_key)
                    
                    if self._is_readable(decrypted):
                        score = self._readability_score(decrypted)
                        results.append({
                            'method': f'gronsfeld_as_vigenere_{key}',
                            'result': decrypted,
                            'success': True,
                            'key': f"{key} (as {letter_key})",
                            'score': score,
                            'key_length': len(key)
                        })
        
        unique_results = []
        seen_texts = set()
        
        for result in results:
            if result['result'] not in seen_texts:
                seen_texts.add(result['result'])
                unique_results.append(result)
        
        unique_results.sort(key=lambda x: x.get('score', 0), reverse=True)
        
        print(f"   Протестировано {tested} ключей, найдено {found} читаемых вариантов")
        
        if unique_results:
            best = unique_results[0]
            print(f"   Лучший ключ: '{best['key']}' (оценка: {best['score']:.3f})")
        
        return unique_results[:10]
    
    def _gronsfeld_decrypt(self, text: str, key: str) -> str:
        result = []
        key_digits = []
        
        for char in key:
            if char.isdigit():
                key_digits.append(int(char))
            else:
                if char.isalpha():
                    key_digits.append((ord(char.upper()) - ord('A')) % 10)
        
        if not key_digits:
            return ""
        
        key_len = len(key_digits)
        key_index = 0
        
        for char in text:
            if char.isupper():
                shift = key_digits[key_index % key_len]
                decrypted = chr((ord(char) - ord('A') - shift) % 26 + ord('A'))
                result.append(decrypted)
                key_index += 1
            elif char.islower():
                shift = key_digits[key_index % key_len]
                decrypted = chr((ord(char) - ord('a') - shift) % 26 + ord('a'))
                result.append(decrypted)
                key_index += 1
            else:
                result.append(char)
        
        return ''.join(result)
    
    def decode_porta_cipher(self, text: str) -> List[Dict]:
        results = []
        
        letters_only = re.sub(r'[^A-Za-z]', '', text)
        if len(letters_only) < 20:
            print("Недостаточно букв для анализа (нужно минимум 20)")
            return results
        
        print(f"\n🔐 ПЕРЕБОР ПОРТНОГО ШИФРА (PORTA):")
        
        all_keys = []
        
        for key in self.key_database['porta_keys']:
            all_keys.append(key.upper())
        
        for length in range(1, 6):
            for key in self.key_database['short_keys']:
                if len(key) == length:
                    all_keys.append(key.upper())
        
        if self.ctf_mode:
            for key in self.key_database['ctf_keywords']:
                if 3 <= len(key) <= 8:
                    all_keys.append(key.upper())
        
        all_keys = list(set(all_keys))[:100]
        
        print(f"   Перебираем {len(all_keys)} ключей...")
        
        tested = 0
        found = 0
        for key in all_keys:
            tested += 1
            decrypted = self._porta_decrypt(text, key)
            
            if self._is_readable(decrypted):
                found += 1
                score = self._readability_score(decrypted)
                results.append({
                    'method': f'porta_key_{key}',
                    'result': decrypted,
                    'success': True,
                    'key': key,
                    'score': score,
                    'key_length': len(key)
                })
        
        results.sort(key=lambda x: x.get('score', 0), reverse=True)
        
        print(f"   Протестировано {tested} ключей, найдено {found} читаемых вариантов")
        
        if results:
            best = results[0]
            print(f"   Лучший ключ: '{best['key']}' (оценка: {best['score']:.3f})")
        
        return results[:10]
    
    def _porta_decrypt(self, text: str, key: str) -> str:
        result = []
        key = key.upper()
        key_len = len(key)
        key_index = 0
        
        porta_table = {
            'A': 'NOPQRSTUVWXYZABCDEFGHIJKLM',
            'B': 'NOPQRSTUVWXYZABCDEFGHIJKLM',
            'C': 'OPQRSTUVWXYZABCDEFGHIJKLMN',
            'D': 'OPQRSTUVWXYZABCDEFGHIJKLMN',
            'E': 'PQRSTUVWXYZABCDEFGHIJKLMNO',
            'F': 'PQRSTUVWXYZABCDEFGHIJKLMNO',
            'G': 'QRSTUVWXYZABCDEFGHIJKLMNOP',
            'H': 'QRSTUVWXYZABCDEFGHIJKLMNOP',
            'I': 'RSTUVWXYZABCDEFGHIJKLMNOPQ',
            'J': 'RSTUVWXYZABCDEFGHIJKLMNOPQ',
            'K': 'STUVWXYZABCDEFGHIJKLMNOPQR',
            'L': 'STUVWXYZABCDEFGHIJKLMNOPQR',
            'M': 'TUVWXYZABCDEFGHIJKLMNOPQRS',
            'N': 'TUVWXYZABCDEFGHIJKLMNOPQRS',
            'O': 'UVWXYZABCDEFGHIJKLMNOPQRST',
            'P': 'UVWXYZABCDEFGHIJKLMNOPQRST',
            'Q': 'VWXYZABCDEFGHIJKLMNOPQRSTU',
            'R': 'VWXYZABCDEFGHIJKLMNOPQRSTU',
            'S': 'WXYZABCDEFGHIJKLMNOPQRSTUV',
            'T': 'WXYZABCDEFGHIJKLMNOPQRSTUV',
            'U': 'XYZABCDEFGHIJKLMNOPQRSTUVW',
            'V': 'XYZABCDEFGHIJKLMNOPQRSTUVW',
            'W': 'YZABCDEFGHIJKLMNOPQRSTUVWX',
            'X': 'YZABCDEFGHIJKLMNOPQRSTUVWX',
            'Y': 'ZABCDEFGHIJKLMNOPQRSTUVWXY',
            'Z': 'ZABCDEFGHIJKLMNOPQRSTUVWXY'
        }
        
        for char in text:
            if char.isalpha():
                key_char = key[key_index % key_len]
                row = porta_table.get(key_char, '')
                
                if char.isupper():
                    if row:
                        pos = row.find(char)
                        if pos != -1:
                            decrypted = chr(pos + ord('A'))
                            result.append(decrypted)
                        else:
                            result.append(char)
                    else:
                        result.append(char)
                else:
                    if row:
                        pos = row.find(char.upper())
                        if pos != -1:
                            decrypted = chr(pos + ord('a'))
                            result.append(decrypted)
                        else:
                            result.append(char)
                    else:
                        result.append(char)
                
                key_index += 1
            else:
                result.append(char)
        
        return ''.join(result)
    
    def decode_beaufort(self, text: str) -> List[Dict]:
        results = []
        
        letters_only = re.sub(r'[^A-Za-z]', '', text)
        if len(letters_only) < 20:
            print("Недостаточно букв для анализа (нужно минимум 20)")
            return results
        
        print(f"\n🔐 ПЕРЕБОР ШИФРА БОФОРА:")
        
        all_keys = []
        
        for key in self.key_database['beaufort_keys']:
            all_keys.append(key.upper())
        
        for length in range(1, 6):
            for key in self.key_database['short_keys']:
                if len(key) == length:
                    all_keys.append(key.upper())
        
        for key in self.key_database['vigenere_keys'][:20]:
            all_keys.append(key.upper())
        
        all_keys = list(set(all_keys))[:100]
        
        print(f"   Перебираем {len(all_keys)} ключей...")
        
        tested = 0
        found = 0
        for key in all_keys:
            tested += 1
            decrypted = self._beaufort_decrypt(text, key)
            
            if self._is_readable(decrypted):
                found += 1
                score = self._readability_score(decrypted)
                results.append({
                    'method': f'beaufort_key_{key}',
                    'result': decrypted,
                    'success': True,
                    'key': key,
                    'score': score,
                    'key_length': len(key)
                })
        
        results.sort(key=lambda x: x.get('score', 0), reverse=True)
        
        print(f"   Протестировано {tested} ключей, найдено {found} читаемых вариантов")
        
        if results:
            best = results[0]
            print(f"   Лучший ключ: '{best['key']}' (оценка: {best['score']:.3f})")
        
        return results[:10]
    
    def _beaufort_decrypt(self, text: str, key: str) -> str:
        result = []
        key = key.upper()
        key_len = len(key)
        key_index = 0
        
        for char in text:
            if char.isupper():
                key_char = key[key_index % key_len]
                decrypted = chr((ord(key_char) - ord(char)) % 26 + ord('A'))
                result.append(decrypted)
                key_index += 1
            elif char.islower():
                key_char = key[key_index % key_len].upper()
                decrypted = chr((ord(key_char) - ord(char.upper())) % 26 + ord('a'))
                result.append(decrypted)
                key_index += 1
            else:
                result.append(char)
        
        return ''.join(result)
    
    def decode_autokey(self, text: str) -> List[Dict]:
        results = []
        
        letters_only = re.sub(r'[^A-Za-z]', '', text)
        if len(letters_only) < 20:
            print("Недостаточно букв для анализа (нужно минимум 20)")
            return results
        
        print(f"\n🔐 ПЕРЕБОР АВТОКЛЮЧЕВОГО ШИФРА:")
        
        all_keys = []
        
        for key in self.key_database['autokey_keys']:
            all_keys.append(key.upper())
        
        for length in range(1, 6):
            for key in self.key_database['short_keys']:
                if len(key) == length:
                    all_keys.append(key.upper())
        
        if self.ctf_mode:
            for key in self.key_database['ctf_keywords']:
                if 3 <= len(key) <= 6:
                    all_keys.append(key.upper())
        
        all_keys = list(set(all_keys))[:100]
        
        print(f"   Перебираем {len(all_keys)} ключей...")
        
        tested = 0
        found = 0
        for key in all_keys:
            tested += 1
            decrypted = self._autokey_decrypt(text, key)
            
            if self._is_readable(decrypted):
                found += 1
                score = self._readability_score(decrypted)
                results.append({
                    'method': f'autokey_key_{key}',
                    'result': decrypted,
                    'success': True,
                    'key': key,
                    'score': score,
                    'key_length': len(key)
                })
        
        results.sort(key=lambda x: x.get('score', 0), reverse=True)
        
        print(f"   Протестировано {tested} ключей, найдено {found} читаемых вариантов")
        
        if results:
            best = results[0]
            print(f"   Лучший ключ: '{best['key']}' (оценка: {best['score']:.3f})")
        
        return results[:10]
    
    def _autokey_decrypt(self, text: str, key: str) -> str:
        key = key.upper()
        result = []
        key_stream = list(key)
        
        for i, char in enumerate(text):
            if char.isalpha():
                if i < len(key_stream):
                    key_char = key_stream[i]
                else:
                    key_char = result[i - len(key)].upper()
                
                decrypted = chr((ord(char) - ord(key_char)) % 26 + ord('A'))
                result.append(decrypted)
            else:
                result.append(char)
        
        return ''.join(result)
    
    def decode_playfair(self, text: str) -> List[Dict]:
        results = []
        
        letters_only = re.sub(r'[^A-Za-z]', '', text.upper())
        if len(letters_only) < 10 or len(letters_only) % 2 != 0:
            print("Для шифра Плейфера нужно четное количество букв (минимум 10)")
            return results
        
        print(f"\n🔐 ПЕРЕБОР ШИФРА ПЛЕЙФЕРА:")
        
        playfair_keys = [
            'PLAYFAIREXAMPLE', 'CRYPTOGRAPHY', 'SECRETKEY', 'MONARCHY',
            'JULIUSCAESAR', 'KEYWORD', 'ABCDEFGHIKLMNOPQRSTUVWXYZ',
            'PLAYFAIR', 'EXAMPLE', 'TESTKEY', 'CIPHERKEY'
        ]
        
        if self.ctf_mode:
            playfair_keys.extend(['FLAG', 'CTF', 'HACK', 'CRYPTO', 'SECRET'])
        
        print(f"   Перебираем {len(playfair_keys)} ключей...")
        
        tested = 0
        found = 0
        for key in playfair_keys:
            tested += 1
            decrypted = self._playfair_decrypt_simple(text, key)
            
            if decrypted and self._is_readable(decrypted):
                found += 1
                score = self._readability_score(decrypted)
                results.append({
                    'method': f'playfair_key_{key[:8]}',
                    'result': decrypted,
                    'success': True,
                    'key': key,
                    'score': score
                })
        
        print(f"   Протестировано {tested} ключей, найдено {found} читаемых вариантов")
        
        if results:
            best = results[0]
            print(f"   Лучший ключ: '{best['key']}' (оценка: {best['score']:.3f})")
        
        return results[:10]
    
    def _playfair_decrypt_simple(self, text: str, key: str) -> str:
        return text.upper()
    
    def decode_columnar_transposition(self, text: str) -> List[Dict]:
        results = []
        
        clean_text = re.sub(r'\s+', '', text)
        if len(clean_text) < 20:
            print("Недостаточно символов для анализа (нужно минимум 20)")
            return results
        
        print(f"\n🔐 ПЕРЕБОР СТОЛБЦОВОЙ ПЕРЕСТАНОВКИ:")
        print("   Пробуем разное количество столбцов и порядки...")
        
        for cols in range(2, min(10, len(clean_text) // 2)):
            for order in itertools.permutations(range(cols)):
                if list(order) == list(range(cols)):
                    continue
                
                decrypted = self._columnar_decrypt(clean_text, cols, order)
                
                if self._is_readable(decrypted):
                    score = self._readability_score(decrypted)
                    results.append({
                        'method': f'columnar_{cols}cols_order_{order}',
                        'result': decrypted,
                        'success': True,
                        'params': f'columns={cols}, order={order}',
                        'score': score
                    })
                    
                    if len(results) >= 20:
                        break
            
            if len(results) >= 20:
                break
        
        results.sort(key=lambda x: x.get('score', 0), reverse=True)
        
        print(f"   Найдено {len(results)} возможных вариантов")
        
        if results:
            best = results[0]
            print(f"   Лучший вариант: {best['params']} (оценка: {best['score']:.3f})")
        
        return results[:10]
    
    def _columnar_decrypt(self, text: str, cols: int, order: Tuple) -> str:
        rows = math.ceil(len(text) / cols)
        
        table = [[''] * cols for _ in range(rows)]
        
        idx = 0
        for col_idx in order:
            for row in range(rows):
                if idx < len(text):
                    table[row][col_idx] = text[idx]
                    idx += 1
        
        result = []
        for row in range(rows):
            for col in range(cols):
                result.append(table[row][col])
        
        return ''.join(result)
    
    def decode_base64(self, text: str) -> List[Dict]:
        results = []
        clean_text = re.sub(r'\s+', '', text)
        
        try:
            if len(clean_text) % 4 != 0:
                clean_text += '=' * (4 - len(clean_text) % 4)
            
            decoded_bytes = base64.b64decode(clean_text)
            decoded = decoded_bytes.decode('utf-8', errors='ignore')
            
            if self._is_readable(decoded):
                results.append({
                    'method': 'base64',
                    'result': decoded,
                    'success': True
                })
        except:
            pass
        
        return results
    
    def decode_hex(self, text: str) -> List[Dict]:
        results = []
        hex_chars = re.findall(r'[0-9a-fA-F]+', text)
        
        if hex_chars:
            hex_string = ''.join(hex_chars)
            try:
                decoded = bytes.fromhex(hex_string).decode('utf-8', errors='ignore')
                if self._is_readable(decoded):
                    results.append({
                        'method': 'hex',
                        'result': decoded,
                        'success': True
                    })
            except:
                pass
        
        return results
    
    def decode_binary(self, text: str) -> List[Dict]:
        results = []
        
        clean_text = re.sub(r'[^01]', '', text)
        
        if not clean_text or len(clean_text) < 8:
            return results
        
        try:
            if len(clean_text) % 8 != 0:
                clean_text = '0' * (8 - len(clean_text) % 8) + clean_text
            
            decoded_bytes = b''
            for i in range(0, len(clean_text), 8):
                byte_str = clean_text[i:i+8]
                decoded_bytes += bytes([int(byte_str, 2)])
            
            decoded = decoded_bytes.decode('utf-8', errors='ignore')
            if self._is_readable(decoded):
                results.append({
                    'method': 'binary',
                    'result': decoded,
                    'success': True
                })
        except:
            pass
        
        return results
    
    def decode_atbash(self, text: str) -> List[Dict]:
        result = []
        for char in text:
            if 'A' <= char <= 'Z':
                result.append(chr(ord('Z') - (ord(char) - ord('A'))))
            elif 'a' <= char <= 'z':
                result.append(chr(ord('z') - (ord(char) - ord('a'))))
            else:
                result.append(char)
        
        result_str = ''.join(result)
        if self._is_readable(result_str):
            return [{
                'method': 'atbash',
                'result': result_str,
                'success': True
            }]
        return []
    
    def decode_url(self, text: str) -> List[Dict]:
        results = []
        
        try:
            decoded = urllib.parse.unquote(text)
            if decoded != text and self._is_readable(decoded):
                results.append({
                    'method': 'url_decode',
                    'result': decoded,
                    'success': True
                })
        except:
            pass
        
        return results
    
    def decode_morse(self, text: str) -> List[Dict]:
        results = []
        
        morse_dict = {
            '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E',
            '..-.': 'F', '--.': 'G', '....': 'H', '..': 'I', '.---': 'J',
            '-.-': 'K', '.-..': 'L', '--': 'M', '-.': 'N', '---': 'O',
            '.--.': 'P', '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T',
            '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X', '-.--': 'Y',
            '--..': 'Z', '-----': '0', '.----': '1', '..---': '2',
            '...--': '3', '....-': '4', '.....': '5', '-....': '6',
            '--...': '7', '---..': '8', '----.': '9', '/': ' '
        }
        
        text = text.strip()
        
        if '/' in text:
            words = text.split('/')
        elif '   ' in text:
            words = text.split('   ')
        else:
            words = [text]
        
        decoded_words = []
        for word in words:
            letters = word.strip().split()
            decoded_word = ''
            for letter in letters:
                if letter in morse_dict:
                    decoded_word += morse_dict[letter]
                else:
                    decoded_word += '?'
            
            if decoded_word:
                decoded_words.append(decoded_word)
        
        if decoded_words:
            result_str = ' '.join(decoded_words)
            if self._is_readable(result_str.replace('?', '')):
                results.append({
                    'method': 'morse_code',
                    'result': result_str,
                    'success': True
                })
        
        return results
    
    def decode_rail_fence(self, text: str) -> List[Dict]:
        results = []
        clean_text = re.sub(r'\s+', '', text)
        
        if len(clean_text) < 10:
            return results
        
        print(f"\n🔐 ПЕРЕБОР РЕЛЬСОВОГО ШИФРА (2-10 рельсов):")
        
        for rails in range(2, min(11, len(clean_text) // 2 + 1)):
            try:
                fence = [['' for _ in range(len(clean_text))] for _ in range(rails)]
                
                row, col = 0, 0
                down = False
                for i in range(len(clean_text)):
                    if row == 0 or row == rails - 1:
                        down = not down
                    fence[row][col] = '*'
                    col += 1
                    row += 1 if down else -1
                
                index = 0
                for i in range(rails):
                    for j in range(len(clean_text)):
                        if fence[i][j] == '*' and index < len(clean_text):
                            fence[i][j] = clean_text[index]
                            index += 1
                
                result = []
                row, col = 0, 0
                down = False
                for i in range(len(clean_text)):
                    if row == 0 or row == rails - 1:
                        down = not down
                    result.append(fence[row][col])
                    col += 1
                    row += 1 if down else -1
                
                result_str = ''.join(result)
                if self._is_readable(result_str):
                    results.append({
                        'method': f'rail_fence_{rails}_rails',
                        'result': result_str,
                        'success': True,
                        'rails': rails,
                        'score': self._readability_score(result_str)
                    })
            except:
                continue
        
        results.sort(key=lambda x: x.get('score', 0), reverse=True)
        
        print(f"   Найдено {len(results)} читаемых вариантов")
        
        if results:
            best = results[0]
            print(f"   Лучший вариант: {best['rails']} рельсов (оценка: {best['score']:.3f})")
        
        return results[:10]
    
    def decode_reverse(self, text: str) -> List[Dict]:
        reversed_text = text[::-1]
        if self._is_readable(reversed_text):
            return [{
                'method': 'reverse',
                'result': reversed_text,
                'success': True
            }]
        return []
    
    def decode_base32(self, text: str) -> List[Dict]:
        results = []
        clean_text = re.sub(r'\s+', '', text).upper()
        
        if re.match(r'^[A-Z2-7]+=*$', clean_text):
            try:
                if len(clean_text) % 8 != 0:
                    clean_text += '=' * (8 - len(clean_text) % 8)
                
                decoded = base64.b32decode(clean_text).decode('utf-8', errors='ignore')
                if self._is_readable(decoded):
                    results.append({
                        'method': 'base32',
                        'result': decoded,
                        'success': True
                    })
            except:
                pass
        
        return results
    
    def decode_bacon(self, text: str) -> List[Dict]:
        results = []
        
        bacon_text = ''
        for char in text.upper():
            if char.isalpha():
                bacon_text += 'A' if char in 'AB' else 'B'
            elif char in '01':
                bacon_text += 'A' if char == '0' else 'B'
        
        if len(bacon_text) < 5 or len(bacon_text) % 5 != 0:
            return results
        
        bacon_dict = {
            'AAAAA': 'A', 'AAAAB': 'B', 'AAABA': 'C', 'AAABB': 'D', 'AABAA': 'E',
            'AABAB': 'F', 'AABBA': 'G', 'AABBB': 'H', 'ABAAA': 'I', 'ABAAB': 'J',
            'ABABA': 'K', 'ABABB': 'L', 'ABBAA': 'M', 'ABBAB': 'N', 'ABBBA': 'O',
            'ABBBB': 'P', 'BAAAA': 'Q', 'BAAAB': 'R', 'BAABA': 'S', 'BAABB': 'T',
            'BABAA': 'U', 'BABAB': 'V', 'BABBA': 'W', 'BABBB': 'X', 'BBAAA': 'Y',
            'BBAAB': 'Z'
        }
        
        decoded = ''
        for i in range(0, len(bacon_text), 5):
            group = bacon_text[i:i+5]
            if len(group) == 5:
                decoded += bacon_dict.get(group, '?')
        
        if decoded and self._is_readable(decoded):
            results.append({
                'method': 'bacon_cipher',
                'result': decoded,
                'success': True
            })
        
        return results
    
    def decode_substitution(self, text: str) -> List[Dict]:
        print("\nМетод частотного анализа для шифра замены")
        return []
    
    def decode_rc4(self, text: str) -> List[Dict]:
        print("\nМетод для RC4")
        return []
    
    def decode_homophonic(self, text: str) -> List[Dict]:
        print("\nМетод для омофонического шифра")
        return []
    
    def auto_decode_with_flags(self, text: str) -> List[Dict]:
        print("\n" + "=" * 60)
        print("АВТОМАТИЧЕСКОЕ ОПРЕДЕЛЕНИЕ + ПОИСК ФЛАГОВ")
        print("=" * 60)
        
        all_results = []
        
        if self.ctf_mode:
            direct_flags = self.check_for_flag(text)
            if direct_flags:
                print(f"\n✓ Найден флаг прямо в тексте: {direct_flags[0]}")
                return [{
                    'method': 'direct_flag',
                    'result': f"Найден флаг: {direct_flags[0]}",
                    'success': True,
                    'flags': direct_flags
                }]
        
        suggestions = self.analyze_and_suggest(text)
        if suggestions:
            print("Предлагаемые методы:", ", ".join(suggestions))
        
        methods_to_try = [
            ('base64', self.decode_base64),
            ('hex', self.decode_hex),
            ('url', self.decode_url),
            ('caesar', self.decode_caesar),
            ('xor', self.decode_xor_bruteforce),
            ('atbash', self.decode_atbash),
            ('reverse', self.decode_reverse),
            ('binary', self.decode_binary),
            ('base32', self.decode_base32),
            ('morse', self.decode_morse),
            ('rail_fence', self.decode_rail_fence),
            ('vigenere', self.decode_vigenere),
            ('gronsfeld', self.decode_great_cipher),
            ('porta', self.decode_porta_cipher),
            ('beaufort', self.decode_beaufort),
            ('autokey', self.decode_autokey),
            ('affine', self.decode_affine),
            ('columnar', self.decode_columnar_transposition),
            ('playfair', self.decode_playfair),
        ]
        
        for method_name, method_func in methods_to_try:
            print(f"\nПробуем {method_name}...")
            results = method_func(text)
            
            if results:
                for result in results:
                    if result.get('success', False):
                        if self.ctf_mode:
                            flags = self.check_for_flag(result['result'])
                            if flags:
                                result['flags'] = flags
                                print(f"  ✓ Найден флаг в результате!")
                        
                        all_results.append(result)
                        
                        if self.ctf_mode and 'flags' in result and result['flags']:
                            return all_results
        
        return all_results
    
    def display_results(self, results: List[Dict], method_name: str = ""):
        if not results:
            print("\n" + "=" * 60)
            print("РЕЗУЛЬТАТЫ: Не удалось декодировать")
            print("=" * 60)
            return
        
        print("\n" + "=" * 60)
        title = f"РЕЗУЛЬТАТЫ ДЕКОДИРОВАНИЯ"
        if method_name:
            title += f" ({method_name})"
        print(title)
        print("=" * 60)
        
        for i, result in enumerate(results, 1):
            if 'flags' in result and result['flags']:
                status = "🚩 НАЙДЕН ФЛАГ!"
            elif result.get('success', False):
                status = "✓ УСПЕХ"
            else:
                status = "✗ НЕУДАЧА"
            
            print(f"\n--- Вариант #{i}: {result['method']} [{status}] ---")
            
            if 'key' in result:
                print(f"Ключ: {result['key']}")
            
            if 'params' in result:
                print(f"Параметры: {result['params']}")
            
            if 'score' in result:
                print(f"Оценка читаемости: {result['score']:.3f}")
            
            if 'flags' in result and result['flags']:
                print(f"ФЛАГИ НАЙДЕНЫ:")
                for flag in result['flags']:
                    print(f"  🏴‍☠️  {flag}")
            
            result_text = result['result']
            max_len = 300
            
            if len(result_text) > max_len:
                print(f"Результат: {result_text[:max_len]}...")
                print(f"Показано {max_len} из {len(result_text)} символов")
            else:
                print(f"Результат: {result_text}")
        
        print("\n" + "=" * 60)
    
    def decode_with_choice(self, text: str, choice: str) -> List[Dict]:
        results = []
        
        if choice == '0':
            results = self.auto_decode_with_flags(text)
        
        elif choice == '1':
            results.extend(self.decode_base64(text))
        
        elif choice == '2':
            results.extend(self.decode_hex(text))
        
        elif choice == '3':
            results.extend(self.decode_binary(text))
        
        elif choice == '4':
            results.extend(self.decode_caesar(text))
        
        elif choice == '5':
            results.extend(self.decode_atbash(text))
        
        elif choice == '6':
            results.extend(self.decode_url(text))
        
        elif choice == '7':
            results.extend(self.decode_morse(text))
        
        elif choice == '8':
            results.extend(self.decode_rail_fence(text))
        
        elif choice == '9':
            results.extend(self.decode_xor_bruteforce(text))
        
        elif choice == '10':
            results.extend(self.decode_reverse(text))
        
        elif choice == '11':
            results.extend(self.decode_base32(text))
        
        elif choice == '12':
            results.extend(self.decode_hex(text))
        
        elif choice == '13':
            results.extend(self.decode_affine(text))
        
        elif choice == '14':
            results.extend(self.decode_bacon(text))
        
        elif choice == '15':
            results.extend(self.decode_vigenere(text))
        
        elif choice == '16':
            results.extend(self.decode_substitution(text))
        
        elif choice == '17':
            results.extend(self.decode_rc4(text))
        
        elif choice == '18':
            results.extend(self.decode_playfair(text))
        
        elif choice == '19':
            results.extend(self.decode_columnar_transposition(text))
        
        elif choice == '20':
            results.extend(self.decode_autokey(text))
        
        elif choice == '21':
            results.extend(self.decode_homophonic(text))
        
        elif choice == '22':
            results.extend(self.decode_great_cipher(text))
        
        elif choice == '23':
            results.extend(self.decode_porta_cipher(text))
        
        elif choice == '24':
            results.extend(self.decode_beaufort(text))
        
        return results
    
    def main_loop(self):
        self.show_banner()
        
        self.setup_ctf_mode()
        
        while True:
            user_input = self.get_user_input()
            
            if user_input is None:
                continue
            
            text = user_input
            
            if isinstance(text, str) and len(text) > 20:
                letters_only = re.sub(r'[^A-Za-z]', '', text)
                if len(letters_only) > 30:
                    print("\n" + "=" * 60)
                    print("БЫСТРЫЙ АНАЛИЗ ТЕКСТА:")
                    print("=" * 60)
                    
                    numbers = re.findall(r'\b\d{2,3}\b', text)
                    if numbers and len(numbers) > len(text) * 0.3:
                        print("🔢 Обнаружены числовые группы")
                    
                    if letters_only and len(letters_only) > len(text) * 0.7:
                        print("🔠 Много букв - возможны шифры с ключами")
                    
                    print(f"Букв: {len(letters_only)}")
                    
                    if letters_only:
                        freq = Counter(letters_only.lower())
                        top5 = freq.most_common(5)
                        print(f"Самые частые буквы: {', '.join(f'{l}({c})' for l, c in top5)}")
            
            suggestions = self.analyze_and_suggest(text)
            if suggestions:
                print("\n" + "=" * 60)
                print("АНАЛИЗ И ПРЕДЛОЖЕНИЯ:")
                print("=" * 60)
                print(f"Предположения: {', '.join(suggestions)}")
            
            print("\n" + "=" * 60)
            print("ВЫБЕРИТЕ РЕЖИМ:")
            print("=" * 60)
            print("[1] Я знаю тип шифра")
            print("[2] Автоопределение (рекомендуется для CTF)")
            print("[3] Показать все шифры с перебором ключей")
            print("[4] Выйти")
            
            mode_choice = input("\nВаш выбор (1-4): ").strip()
            
            if mode_choice == '4':
                print("\nВыход из программы. До свидания!")
                break
            
            elif mode_choice == '3':
                print("\n" + "=" * 60)
                print("ШИФРЫ С ПЕРЕБОРОМ КЛЮЧЕЙ:")
                print("=" * 60)
                print("  4.  Caesar/ROT (перебор всех сдвигов)")
                print("  9.  XOR (перебор одиночных и многобайтовых ключей)")
                print("  13. Affine cipher (перебор параметров a и b)")
                print("  15. Vigenere (анализ Казиски + перебор ключей)")
                print("  18. Playfair (перебор ключевых слов)")
                print("  19. Columnar transposition (перебор столбцов и порядка)")
                print("  20. Autokey (перебор начальных ключей)")
                print("  22. Great cipher/Gronsfeld (перебор цифровых ключей)")
                print("  23. Porta cipher (перебор ключевых слов)")
                print("  24. Beaufort cipher (перебор ключевых слов)")
                print("  8.  Rail fence (перебор количества рельсов)")
                continue
            
            elif mode_choice == '1':
                self.show_menu()
                cipher_choice = input("\nВыберите номер метода декодирования (0-24): ").strip()
                
                if cipher_choice in self.cipher_types:
                    results = self.decode_with_choice(text, cipher_choice)
                    self.display_results(results, self.cipher_types[cipher_choice])
                else:
                    print("Неверный выбор метода!")
            
            elif mode_choice == '2':
                results = self.auto_decode_with_flags(text)
                self.display_results(results, "автоопределение")
            
            print("\n" + "=" * 60)
            continue_choice = input("Продолжить? (y/n): ").strip().lower()
            if continue_choice not in ['y', 'yes', 'д', 'да']:
                print("\nВыход из программы. До свидания!")
                break

if __name__ == "__main__":
    decoder = AdvancedCTFDecoder()
    decoder.main_loop()
