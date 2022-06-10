import string
import sys
import re

class FileTooShortException(Exception):
    pass

class WatermarkEncryptor():
    def read_file(self, file):
        raise NotImplementedError()

    def encode_message(self, message, output_file):
        raise NotImplementedError()

    def decode_message(self):
        raise NotImplementedError()

class SpaceNewLineWatermark(WatermarkEncryptor):
    def _clean_data(self):
        for i, line in enumerate(self._data):
            line = line.rstrip() + '\n'
            self._data[i] = line

    def read_file(self, file):
        with open(file, 'r', encoding="utf8") as file:
            self._data = file.readlines()

    def encode_message(self, message, output_file):
        if (type(message) == str):
            message = message.encode()

        file_lines = len(self._data)
        expected_size = len(message) * 8

        if file_lines < expected_size:
            raise FileTooShortException(f'Need at least {expected_size} lines, got {file_lines} in input file')

        self._clean_data()

        idx = 0
        for byte in message:
            byte_str = f'{byte:08b}'
            for c in byte_str:
                line = self._data[idx].rstrip()
                if c == '1':
                    line += ' '
                self._data[idx] = line + '\n'
                idx += 1

        with open(output_file, 'w', encoding="utf8") as file:
            file.writelines(self._data)

    def decode_message(self):
        byte_arr = bytearray()

        for idx in range(0, len(self._data), 8):
            if len(self._data) - idx < 8:
                break

            byte = 0
            for j in range(idx, idx + 8):
                line = self._data[j].rstrip('\n')
                byte <<= 1
                if len(line) and line[-1] == ' ':
                    byte |= 1

            byte_arr.append(byte)

        byte_arr = bytes(byte_arr.rstrip(b'\x00'))
        return byte_arr

class DoubleScapeWatermark(WatermarkEncryptor):
    def _clean_data(self):
        self._data = re.sub(r'(?<! )  (?! )', ' ', self._data, flags=re.MULTILINE)

    def read_file(self, file):
        with open(file, 'r', encoding="utf8") as file:
            self._data = file.read()

    def encode_message(self, message, output_file):
        if (type(message) == str):
            message = message.encode()

        self._clean_data()
        single_spaces = [*re.finditer(r'(?<! ) (?! )', self._data, flags=re.MULTILINE)]

        found_spaces = len(single_spaces)
        expected_size = len(message) * 8

        if found_spaces < expected_size:
            raise FileTooShortException(f'Need at least {expected_size} single spaces, got {found_spaces} in input file')

        bits = ''.join(f'{byte:08b}' for byte in message)
        bits_index = 0

        def replace_space(match):
            nonlocal bits_index
            replacement = ' '
            if bits_index < len(bits) and bits[bits_index] == '1':
                replacement = '  '
            bits_index += 1
            return replacement

        self._data = re.sub(r'(?<! ) (?! )', replace_space, self._data, count=len(bits), flags=re.MULTILINE)

        with open(output_file, 'w', encoding="utf8") as file:
            file.write(self._data)

    def decode_message(self):
        spaces = re.findall(r'(?<! ) {1,2}(?! )', self._data, flags=re.MULTILINE)
        bits = ['1' if t == '  ' else '0' for t in spaces]
        bytes_temp = [int(''.join(bits[i:i+8]), 2) for i in range(0, len(bits), 8)]
        return bytes(bytes_temp).rstrip(b'\x00')

class TypoWatermark(WatermarkEncryptor):
    pass

class TagWatermark(WatermarkEncryptor):
    ALLOWED_TAGS = ['dfn', 'em', 'i', 'big', 'u', 'span']

def print_help():
    print('The program hides/unhides watermark message in HTML file')
    print('The template HTML file is cover.html, the message is read')
    print('from mess.txt')
    print('\nSupported options:')
    print('-e <method> - encrypt message to watermark.html')
    print('-d <method> - decrypt message to detect.txt')
    print('\nSupported steganography methods:')
    print('> onespace - hides bits as single spaces at the end of each line')
    print('> doublespace - hides bits as single or double spaces')

def get_encryptor(method):
    if method == 'onespace':
        return SpaceNewLineWatermark()
    if method == 'doublespace':
        return DoubleScapeWatermark()

    print('Unsupported method:', method)
    return None

def parse_hex_file(filename):
    with open(filename, 'r') as file:
        data = file.read()
        data = ''.join(filter(lambda c: c in string.hexdigits, data.lower()))
        if len(data) % 2:
            data += '0'

        return bytes.fromhex(data)

def encrypt_message(method):
    encryptor = get_encryptor(method)
    if not encryptor:
        return

    message = parse_hex_file('mess.txt')
    encryptor.read_file('cover.html')
    try:
        encryptor.encode_message(message, 'watermark.html')
    except FileTooShortException as err:
        print(err)

def decrypt_message(method):
    encryptor = get_encryptor(method)
    if not encryptor:
        return

    encryptor.read_file('watermark.html')
    message = encryptor.decode_message()
    with open('detect.txt', 'w') as file:
        file.write(message.hex())

if __name__ == '__main__':
    args = [
        # (<param>, <no. of arguments>, <function>)
        ('-e', 1, encrypt_message),
        ('-d', 1, decrypt_message),
    ]

    if len(sys.argv) == 1:
        print_help()
        exit()

    for option in args:
        if sys.argv[1] == option[0]:
            expected_arguments = 2 + option[1]
            if len(sys.argv) < expected_arguments:
                print(f'Missing {expected_arguments - len(sys.argv)} arguments for option "{option[0]}"')
            else:
                option[2](sys.argv[2])
            break
    else:
        print('Unknown option:', sys.argv[1])
        print_help()
