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
            '15': 'playfair',
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
        print("ВВЕДИТЕ ЗАКОДИРОВАННУЮ СТРОКУ:")
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
                        'rails': rails
                    })
            except:
                continue
        
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
    
    def decode_reverse(self, text: str) -> List[Dict]:
        reversed_text = text[::-1]
        if self._is_readable(reversed_text):
            return [{
                'method': 'reverse',
                'result': reversed_text,
                'success': True
            }]
        return []
    
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
        
        return all_results
    
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
            
            if self._is_readable(result_str):
                results.append({
                    'method': f'caesar_rot{shift}',
                    'result': result_str,
                    'success': True,
                    'shift': shift
                })
        
        results.sort(key=lambda x: self._readability_score(x['result']), reverse=True)
        return results[:5]
    
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
        
        if len(data) == 0:
            return results
        
        print(f"Bruteforce XOR для {len(data)} байт...")
        
        for key in range(256):
            try:
                decrypted = bytes(b ^ key for b in data)
                decoded = decrypted.decode('utf-8', errors='ignore')
                
                if self._is_readable(decoded):
                    results.append({
                        'method': f'xor_single_byte_{key:02x}({key})',
                        'result': decoded,
                        'success': True,
                        'key': f'{key:02x}'
                    })
                    
                    if len(results) >= 5:
                        break
            except:
                continue
        
        return results
    
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
            
            if 'flags' in result and result['flags']:
                print(f"ФЛАГИ НАЙДЕНЫ:")
                for flag in result['flags']:
                    print(f"  🏴‍☠️  {flag}")
            
            result_text = result['result']
            max_len = 200
            
            if len(result_text) > max_len:
                print(f"Результат: {result_text[:max_len]}...")
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
        
        return results
    
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