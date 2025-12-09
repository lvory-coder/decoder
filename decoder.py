import re
import base64
import string
from collections import Counter
from typing import Dict, List, Optional, Tuple, Any
import binascii
import urllib.parse
import itertools

class AdvancedCTFDecoder:
    def __init__(self):
        self.common_words = {'the', 'and', 'for', 'are', 'but', 'not', 'you', 'all', 'can', 'was',
                            'flag', 'ctf', 'crypto', 'find', 'secret', 'key', 'hidden', 'data',
                            'that', 'with', 'have', 'this', 'from', 'they', 'would', 'there',
                            'hello', 'world', 'test', 'message', 'password', 'admin', 'user'}
        
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
            '15': 'playfair (нужен ключ)',
            '0': 'автоопределение + поиск флага'
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
    
    def show_banner(self):
        banner = """
        ╔══════════════════════════════════════════════════════════╗
        ║                        DECODER                           ║
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
            print("\nДоступные форматы флагов:")
            for i, fmt in enumerate(self.possible_flag_formats, 1):
                flag_example = self._format_to_example(fmt)
                print(f"  {i:2d}. {flag_example}")
            
            print("\nВы можете:")
            print("  1. Выбрать готовый формат")
            print("  2. Ввести свой префикс (например: 'flag{', 'CTF{')")
            print("  3. Использовать регулярное выражение")
            
            choice = input("\nВаш выбор (1-3): ").strip()
            
            if choice == '1':
                fmt_num = input("Номер формата (1-12): ").strip()
                try:
                    idx = int(fmt_num) - 1
                    if 0 <= idx < len(self.possible_flag_formats):
                        self.flag_prefix = self.possible_flag_formats[idx]
                        print(f"Выбран формат: {self._format_to_example(self.flag_prefix)}")
                except:
                    print("Неверный номер, используем стандартный flag{}")
                    self.flag_prefix = r'flag\{[^}]+\}'
            
            elif choice == '2':
                prefix = input("Введите префикс флага (например 'flag{'): ").strip()
                if prefix.endswith('{'):
                    self.flag_prefix = re.escape(prefix) + r'[^}]+}'
                    print(f"Будем искать флаги вида: {prefix}...")
                else:
                    print("Префикс должен заканчиваться на '{', используем flag{")
                    self.flag_prefix = r'flag\{[^}]+\}'
            
            elif choice == '3':
                regex = input("Введите регулярное выражение для флага: ").strip()
                try:
                    re.compile(regex)
                    self.flag_prefix = regex
                    print(f"Регулярное выражение принято: {regex}")
                except:
                    print("Некорректное регулярное выражение, используем flag{}")
                    self.flag_prefix = r'flag\{[^}]+\}'
            
            else:
                self.flag_prefix = r'flag\{[^}]+\}'
                print(f"Используем стандартный формат: flag{{...}}")
        else:
            self.ctf_mode = False
            print("CTF режим отключен")
    
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
    
    def ask_for_xor_key(self):
        print("\n" + "=" * 60)
        print("ВВОД КЛЮЧА ДЛЯ XOR")
        print("=" * 60)
        
        print("Вы можете:")
        print("  1. Ввести ключ как текст (например: 'secret')")
        print("  2. Ввести ключ как hex (например: 736563726574)")
        print("  3. Ввести ключ как числа (например: 115 101 99 114 101 116)")
        print("  4. Не использовать ключ (bruteforce)")
        
        choice = input("\nВаш выбор (1-4): ").strip()
        
        if choice == '1':
            key = input("Введите ключ как текст: ").strip()
            self.known_key = key.encode('utf-8')
        
        elif choice == '2':
            key_hex = input("Введите ключ как hex: ").strip()
            try:
                self.known_key = bytes.fromhex(key_hex)
            except:
                print("Неверный hex формат, bruteforce вместо этого")
                self.known_key = None
        
        elif choice == '3':
            key_nums = input("Введите ключ как числа через пробел: ").strip()
            try:
                nums = [int(x) for x in key_nums.split()]
                self.known_key = bytes(nums)
            except:
                print("Неверный формат чисел, bruteforce вместо этого")
                self.known_key = None
        
        else:
            self.known_key = None
            print("Будет использован bruteforce")
    
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
    
    def show_menu(self):
        print("\n" + "=" * 60)
        print("ДОСТУПНЫЕ ТИПЫ ШИФРОВ / КОДИРОВОК:")
        print("=" * 60)
        
        for key, value in sorted(self.cipher_types.items()):
            print(f"  [{key}] {value}")
        
        print("\n" + "=" * 60)
    
    def get_user_input(self):
        print("\n" + "=" * 60)
        print("ВВЕДИТЕ ЗАКОДИРОВАННУЮ СТРОКУ:")
        print("=" * 60)
        
        print("Введите текст (многострочный ввод - закончите строкой 'END'):")
        lines = []
        while True:
            line = input()
            if line.strip().upper() == 'END':
                break
            lines.append(line)
        
        text = '\n'.join(lines)
        
        if not text.strip():
            print("Ошибка: введена пустая строка!")
            return None
        
        return text
    
    def analyze_and_suggest(self, text: str) -> List[str]:
        suggestions = []
        clean_text = re.sub(r'\s+', '', text)
        
        if re.match(r'^[A-Za-z0-9+/]*={0,2}$', clean_text):
            suggestions.append("base64")
        
        if re.match(r'^[0-9a-fA-F]+$', clean_text) and len(clean_text) % 2 == 0:
            suggestions.append("hex")
        
        binary_clean = text.replace(' ', '').replace('\n', '')
        if re.match(r'^[01]+$', binary_clean):
            suggestions.append("binary")
        
        letters_only = re.sub(r'[^A-Za-z]', '', text)
        if len(letters_only) > 10 and len(letters_only) / len(text) > 0.8:
            suggestions.append("caesar/atbash")
        
        if '%' in text and re.search(r'%[0-9A-Fa-f]{2}', text):
            suggestions.append("url encoding")
        
        hex_match = re.match(r'^[0-9a-fA-F]+$', clean_text)
        if hex_match and len(clean_text) % 2 == 0 and len(clean_text) >= 20:
            suggestions.append("xor (возможно)")
        
        if re.match(r'^[A-Z2-7]+=*$', clean_text):
            suggestions.append("base32")
        
        return suggestions
    
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
            if self.ctf_mode:
                self._check_results_for_flags(results)
        
        elif choice == '5':
            results.extend(self.decode_atbash(text))
        
        elif choice == '6':
            results.extend(self.decode_url(text))
        
        elif choice == '7':
            results.extend(self.decode_morse(text))
        
        elif choice == '8':
            results.extend(self.decode_rail_fence(text))
        
        elif choice == '9':
            print("\n" + "=" * 60)
            key_choice = input("Знаете ли вы ключ для XOR? (y/n): ").strip().lower()
            
            if key_choice in ['y', 'yes', 'д', 'да']:
                self.ask_for_xor_key()
                results.extend(self.decode_xor_with_key(text, self.known_key))
            else:
                results.extend(self.decode_xor_bruteforce(text))
        
        elif choice == '10':
            results.extend(self.decode_reverse(text))
        
        elif choice == '11':
            results.extend(self.decode_base32(text))
        
        elif choice == '12':
            results.extend(self.decode_base16(text))
        
        elif choice == '13':
            results.extend(self.decode_affine(text))
        
        elif choice == '14':
            results.extend(self.decode_bacon(text))
        
        return results
    
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
        
        if not all_results and len(text) < 1000:
            print("\nПробуем комбинации методов...")
            combined_results = self.try_combinations(text)
            all_results.extend(combined_results)
        
        return all_results
    
    def try_combinations(self, text: str) -> List[Dict]:
        results = []
        
        combinations = [
            ['hex', 'base64'],
            ['base64', 'hex'],
            ['base64', 'base64'],
            ['hex', 'hex'],
            ['base64', 'url'],
            ['url', 'base64'],
        ]
        
        for combo in combinations:
            current_text = text
            method_chain = []
            
            for step, method in enumerate(combo):
                if method == 'hex':
                    decoded = self.decode_hex(current_text)
                elif method == 'base64':
                    decoded = self.decode_base64(current_text)
                elif method == 'url':
                    decoded = self.decode_url(current_text)
                elif method == 'binary':
                    decoded = self.decode_binary(current_text)
                else:
                    continue
                
                if not decoded:
                    break
                
                method_chain.append(method)
                current_text = decoded[0]['result']
                
                if self.ctf_mode:
                    flags = self.check_for_flag(current_text)
                    if flags:
                        results.append({
                            'method': ' → '.join(method_chain),
                            'result': current_text,
                            'success': True,
                            'flags': flags
                        })
                        break
        
        return results
    
    def decode_xor_with_key(self, text: str, key: Optional[bytes]) -> List[Dict]:
        results = []
        
        if not key:
            return self.decode_xor_bruteforce(text)
        
        data_formats = []
        
        hex_chars = re.findall(r'[0-9a-fA-F]+', text)
        if hex_chars:
            hex_string = ''.join(hex_chars)
            try:
                data_formats.append(('hex', bytes.fromhex(hex_string)))
            except:
                pass
        
        try:
            clean = re.sub(r'\s+', '', text)
            if len(clean) % 4 == 0:
                data_formats.append(('base64', base64.b64decode(clean + '=' * (-len(clean) % 4))))
        except:
            pass
        
        data_formats.append(('raw', text.encode('utf-8')))
        
        for fmt_name, data in data_formats:
            try:
                if len(key) == 1:
                    decrypted = bytes(b ^ key[0] for b in data)
                else:
                    decrypted = bytes(data[i] ^ key[i % len(key)] for i in range(len(data)))
                
                try:
                    decoded = decrypted.decode('utf-8')
                    if self._is_readable(decoded):
                        results.append({
                            'method': f'xor_with_key_{fmt_name}',
                            'result': decoded,
                            'success': True,
                            'key': key.hex() if len(key) < 20 else key.hex()[:20] + '...'
                        })
                except:
                    try:
                        decoded = decrypted.decode('latin-1')
                        if self._is_readable(decoded):
                            results.append({
                                'method': f'xor_with_key_{fmt_name}_latin1',
                                'result': decoded,
                                'success': True,
                                'key': key.hex() if len(key) < 20 else key.hex()[:20] + '...'
                            })
                    except:
                        pass
            except Exception as e:
                continue
        
        return results
    
    def decode_xor_bruteforce(self, text: str) -> List[Dict]:
        results = []
        
        data = None
        
        hex_chars = re.findall(r'[0-9a-fA-F]+', text)
        if hex_chars:
            hex_string = ''.join(hex_chars)
            try:
                data = bytes.fromhex(hex_string)
            except:
                pass
        
        if not data:
            try:
                data = text.encode('utf-8')
            except:
                return results
        
        print(f"Bruteforce XOR для {len(data)} байт...")
        
        if len(data) > 0:
            print("Пробуем XOR с одним байтом...")
            for key in range(256):
                try:
                    decrypted = bytes(b ^ key for b in data)
                    decoded = decrypted.decode('utf-8', errors='ignore')
                    
                    if self.ctf_mode:
                        flags = self.check_for_flag(decoded)
                        if flags:
                            results.append({
                                'method': f'xor_single_byte_{key:02x}({key})',
                                'result': decoded,
                                'success': True,
                                'flags': flags,
                                'key': f'{key:02x}'
                            })
                            print(f"  Найден флаг с ключом {key:02x}!")
                            if len(results) >= 3:
                                break
                    
                    elif self._is_readable(decoded):
                        results.append({
                            'method': f'xor_single_byte_{key:02x}({key})',
                            'result': decoded,
                            'success': True,
                            'key': f'{key:02x}'
                        })
                        
                        if len(results) >= 10:
                            break
                
                except:
                    continue
        
        if not results and len(data) > 10:
            print("Пробуем XOR с повторяющимся ключом...")
            
            for key_length in [2, 3, 4, 5, 6, 8]:
                for start_pos in range(min(5, len(data) - key_length)):
                    possible_key = data[start_pos:start_pos + key_length]
                    
                    for key_variant in [possible_key]:
                        try:
                            decrypted = bytes(data[i] ^ key_variant[i % key_length] for i in range(len(data)))
                            decoded = decrypted.decode('utf-8', errors='ignore')
                            
                            if self.ctf_mode:
                                flags = self.check_for_flag(decoded)
                                if flags:
                                    results.append({
                                        'method': f'xor_repeating_key_len{key_length}',
                                        'result': decoded,
                                        'success': True,
                                        'flags': flags,
                                        'key': key_variant.hex()
                                    })
                                    break
                            
                            elif self._is_readable(decoded):
                                results.append({
                                    'method': f'xor_repeating_key_len{key_length}',
                                    'result': decoded,
                                    'success': True,
                                    'key': key_variant.hex()
                                })
                        
                        except:
                            continue
                    
                    if results:
                        break
                
                if results:
                    break
        
        return results
    
    def decode_base64(self, text: str) -> List[Dict]:
        results = []
        clean_text = re.sub(r'\s+', '', text)
        
        for i in range(2):
            try:
                padding = 4 - (len(clean_text) % 4)
                if padding != 4:
                    current_text = clean_text + '=' * padding
                else:
                    current_text = clean_text
                
                decoded_bytes = base64.b64decode(current_text)
                
                try:
                    decoded = decoded_bytes.decode('utf-8')
                    if self._is_readable(decoded):
                        results.append({
                            'method': 'base64',
                            'result': decoded,
                            'success': True
                        })
                        
                        if self.ctf_mode and self.check_for_flag(decoded):
                            return results
                except:
                    pass
                
                try:
                    hex_str = decoded_bytes.hex()
                    if len(hex_str) >= 10:
                        if re.match(r'^[A-Za-z0-9+/]*={0,2}$', hex_str):
                            nested = self.decode_base64(hex_str)
                            if nested:
                                results.extend([{
                                    'method': f'base64 → {r["method"]}',
                                    'result': r['result'],
                                    'success': r['success']
                                } for r in nested])
                except:
                    pass
                
            except:
                pass
            
            try:
                decoded = base64.urlsafe_b64decode(clean_text + '=' * (-len(clean_text) % 4))
                decoded_str = decoded.decode('utf-8', errors='ignore')
                if self._is_readable(decoded_str):
                    results.append({
                        'method': 'base64_urlsafe',
                        'result': decoded_str,
                        'success': True
                    })
            except:
                pass
            
            if not results and len(clean_text) > 4:
                clean_text = clean_text[:-1]
            else:
                break
        
        return results
    
    def decode_base32(self, text: str) -> List[Dict]:
        results = []
        clean_text = re.sub(r'\s+', '', text).upper()
        
        if re.match(r'^[A-Z2-7]+=*$', clean_text):
            try:
                padding = 8 - (len(clean_text) % 8)
                if padding != 8:
                    clean_text += '=' * padding
                
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
    
    def decode_base16(self, text: str) -> List[Dict]:
        return self.decode_hex(text)
    
    def decode_affine(self, text: str) -> List[Dict]:
        results = []
        
        letters = ''.join(c for c in text if c.isalpha())
        if len(letters) < 10:
            return results
        
        valid_a_values = [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25]
        
        for a in valid_a_values:
            a_inv = None
            for i in range(26):
                if (a * i) % 26 == 1:
                    a_inv = i
                    break
            
            if a_inv is None:
                continue
            
            for b in range(26):
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
                    results.append({
                        'method': f'affine_a{a}_b{b}',
                        'result': result_str,
                        'success': True,
                        'params': f'a={a}, b={b}'
                    })
        
        results.sort(key=lambda x: self._readability_score(x['result']), reverse=True)
        return results[:5]
    
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
    
    def decode_caesar(self, text: str) -> List[Dict]:
        results = []
        
        letters = ''.join(c for c in text if c.isalpha())
        if len(letters) < 5:
            return results
        
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
            
            if self.ctf_mode:
                flags = self.check_for_flag(result_str)
                if flags:
                    results.append({
                        'method': f'caesar_rot{shift}',
                        'result': result_str,
                        'success': True,
                        'flags': flags,
                        'shift': shift
                    })
                    break
            
            elif self._is_readable(result_str):
                results.append({
                    'method': f'caesar_rot{shift}',
                    'result': result_str,
                    'success': True,
                    'shift': shift
                })
        
        if not self.ctf_mode:
            results.sort(key=lambda x: self._readability_score(x['result']), reverse=True)
        
        return results[:5] if not self.ctf_mode else results
    
    def _check_results_for_flags(self, results: List[Dict]):
        if not self.ctf_mode:
            return
        
        for result in results:
            if 'result' in result:
                flags = self.check_for_flag(result['result'])
                if flags:
                    result['flags'] = flags
                    result['success'] = True
    
    def _is_readable(self, text: str, threshold: float = 0.6) -> bool:
        if len(text) < 5:
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
        
        return ratio > 0.2 or printable_ratio > 0.7
    
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
                    
                    if self.ctf_mode:
                        flags = self.check_for_flag(decoded)
                        if flags:
                            results[-1]['flags'] = flags
            except:
                pass
        
        return results
    
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
                color_start, color_end = "\033[92m", "\033[0m"
            elif result.get('success', False):
                status = "✓ УСПЕХ"
                color_start, color_end = "\033[94m", "\033[0m"
            else:
                status = "✗ НЕУДАЧА"
                color_start, color_end = "\033[91m", "\033[0m"
            
            print(f"\n{color_start}--- Вариант #{i}: {result['method']} [{status}] ---{color_end}")
            
            if 'key' in result:
                print(f"Ключ: {result['key']}")
            
            if 'params' in result:
                print(f"Параметры: {result['params']}")
            
            if 'flags' in result and result['flags']:
                print(f"{color_start}ФЛАГИ НАЙДЕНЫ:{color_end}")
                for flag in result['flags']:
                    print(f"  🏴‍☠️  {flag}")
            
            result_text = result['result']
            max_len = 300
            
            if len(result_text) > max_len:
                if self.ctf_mode and 'flags' in result:
                    flag = result['flags'][0]
                    flag_pos = result_text.find(flag)
                    if flag_pos >= 0:
                        start = max(0, flag_pos - 50)
                        end = min(len(result_text), flag_pos + len(flag) + 50)
                        preview = result_text[start:end]
                        if start > 0:
                            preview = "..." + preview
                        if end < len(result_text):
                            preview = preview + "..."
                        print(f"Результат (фрагмент с флагом): {preview}")
                    else:
                        print(f"Результат: {result_text[:max_len]}...")
                else:
                    print(f"Результат: {result_text[:max_len]}...")
                    print(f"... (еще {len(result_text) - max_len} символов)")
            else:
                print(f"Результат: {result_text}")
        
        print("\n" + "=" * 60)
    
    def main_loop(self):
        self.show_banner()
        
        self.setup_ctf_mode()
        
        while True:
            text = self.get_user_input()
            if text is None:
                continue
            
            suggestions = self.analyze_and_suggest(text)
            if suggestions:
                print("\n" + "=" * 60)
                print("АНАЛИЗ ТЕКСТА:")
                print("=" * 60)
                print(f"Длина: {len(text)} символов")
                print(f"Превью: {text[:100]}{'...' if len(text) > 100 else ''}")
                print(f"\nПредположения: {', '.join(suggestions)}")
            
            print("\n" + "=" * 60)
            print("ВЫБЕРИТЕ РЕЖИМ:")
            print("=" * 60)
            print("[1] Я знаю тип шифра")
            print("[2] Автоопределение (рекомендуется для CTF)")
            print("[3] Выйти")
            
            mode_choice = input("\nВаш выбор (1-3): ").strip()
            
            if mode_choice == '3':
                print("\nВыход из программы. До свидания!")
                break
            
            elif mode_choice == '1':
                self.show_menu()
                cipher_choice = input("\nВыберите номер метода декодирования (0-14): ").strip()
                
                if cipher_choice in self.cipher_types:
                    results = self.decode_with_choice(text, cipher_choice)
                    self.display_results(results, self.cipher_types[cipher_choice])
                else:
                    print("Неверный выбор метода!")
            
            elif mode_choice == '2':
                results = self.auto_decode_with_flags(text)
                self.display_results(results, "автоопределение")
            
            print("\n" + "=" * 60)
            continue_choice = input("Продолжить с другим текстом? (y/n): ").strip().lower()
            if continue_choice not in ['y', 'yes', 'д', 'да']:
                print("\nВыход из программы. До свидания!")
                break

if __name__ == "__main__":
    decoder = AdvancedCTFDecoder()
    decoder.main_loop()