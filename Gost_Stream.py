import sys
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton, QTextEdit

BLOCK_SIZE = 8
KEY_SIZE = 32

table = [
    [1, 15, 13, 0, 5, 7, 10, 4, 9, 2, 3, 14, 6, 11, 8, 12],
    [15, 4, 2, 13, 1, 11, 10, 6, 7, 3, 9, 5, 0, 14, 12, 8],
    [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
    [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
    [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
    [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
    [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
    [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
]

def gost_encrypt_block(left, right, key):
    temp_sum = (left + key) % (2 ** 32)
    substitution_result = 0
    for i in range(8):
        nibble = (temp_sum >> (4 * i)) & 0xF
        substitution_result |= table[i][nibble] << (4 * i)
    shifted_result = (temp_sum << 11) | (temp_sum >> 21)
    final_result = shifted_result & 0xFFFFFFFF
    return right ^ final_result

def gost_encrypted_block(block, keys):
    left = (block >> 32) & 0xFFFFFFFF
    right = block & 0xFFFFFFFF
    for i in range(24):
        left, right = gost_encrypt_block(left, right, keys[i % 8]), left
    for i in range(8):
        left, right = gost_encrypt_block(left, right, keys[7 - i]), left
    return (right << 32) | left

def gost_decrypted_block(block, keys):
    left = (block >> 32) & 0xFFFFFFFF
    right = block & 0xFFFFFFFF
    for i in range(8):
        left, right = gost_encrypt_block(left, right, keys[i]), left
    for i in range(24):
        left, right = gost_encrypt_block(left, right, keys[7 - (i % 8)]), left
    return (right << 32) | left

def stream_chipher(data, keys):
    result = b""
    count = 0
    for i in range(0, len(data), 8):
        chipher_block = gost_encrypted_block(count, keys)
        count += 1
        newkey = chipher_block.to_bytes(8, 'big')

        new_data = data[i:i + 8]
        result += bytes([b ^ k for b, k in zip(new_data, newkey)])

    return result

def stream(data, key):
    int_key = int.from_bytes(key, 'big')
    keys = [(int_key >> (32 * i)) & 0xFFFFFFFF for i in range(8)]
    while len(data) % 8 != 0:
        data += b'\x00'

    return stream_chipher(data, keys)

class GOSTApp(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle('ГОСТ 28147-89 Шифрование/Дешифрование')

        main_layout = QVBoxLayout()

        key_layout = QHBoxLayout()
        key_label = QLabel('Ключ (32 байта):')
        self.key_input = QLineEdit()
        key_layout.addWidget(key_label)
        key_layout.addWidget(self.key_input)
        main_layout.addLayout(key_layout)

        self.data_input = QTextEdit()
        self.data_input.setPlaceholderText('Введите данные для шифрования/дешифрования')
        main_layout.addWidget(self.data_input)

        button_layout = QHBoxLayout()
        self.encrypt_button = QPushButton('Зашифровать')
        self.decrypt_button = QPushButton('Расшифровать')
        button_layout.addWidget(self.encrypt_button)
        button_layout.addWidget(self.decrypt_button)
        main_layout.addLayout(button_layout)

        self.result_output = QTextEdit()
        self.result_output.setReadOnly(True)
        main_layout.addWidget(self.result_output)

        self.setLayout(main_layout)

        self.encrypt_button.clicked.connect(self.encrypt)
        self.decrypt_button.clicked.connect(self.decrypt)

    def encrypt(self):
        key = self.key_input.text().encode('utf-8')
        data = self.data_input.toPlainText().encode('utf-8')
        if len(key) != KEY_SIZE:
            self.result_output.setText('Ошибка: ключ должен быть длиной 32 байта')
            return
        encrypted_data = stream(data, key)
        self.result_output.setText(encrypted_data.hex())

    def decrypt(self):
        key = self.key_input.text().encode('utf-8')
        data = bytes.fromhex(self.data_input.toPlainText())
        if len(key) != KEY_SIZE:
            self.result_output.setText('Ошибка: ключ должен быть длиной 32 байта')
            return
        decrypted_data = stream(data, key)
        self.result_output.setText(decrypted_data.decode('utf-8', errors='ignore'))

if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = GOSTApp()
    ex.show()
    sys.exit(app.exec_())