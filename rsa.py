from Crypto.PublicKey import RSA
from PyQt5 import QtWidgets
from PyQt5.Qt import QApplication
from main_window import Ui_MainWindow
from binascii import Error as PaddingError
from sys import argv as sys_argv, exit as sys_exit
from mineRSA import RSASignature
from yadisk import YaDisk
from os import remove


class Application(QtWidgets.QMainWindow, Ui_MainWindow):
    def __init__(self):
        super().__init__()
        self.setupUi(self)
        self.signature = RSASignature()
        self.public_key_path = "/public.key"
        self.btn_create_from_file.clicked.connect(self.select_file_to_create)
        self.btn_create_from_text.clicked.connect(self.create_from_text)
        self.btn_verify_from_file.clicked.connect(self.select_file_to_verify)
        self.btn_verify_from_text.clicked.connect(self.verify_from_text)
        self.btn_import_signature.clicked.connect(self.import_signature_from_file)
        self.btn_export_signature.clicked.connect(self.export_signature_as_file)
        self.btn_copy_signature.clicked.connect(self.copy_signature)
        self.btn_paste_sign.clicked.connect(self.paste_signature)

    # GET SIGNATURE FROM CLIPBOARD AND PASTE TO @signature_input FIELD
    def paste_signature(self):
        self.signature_input.setText(QApplication.clipboard().text())

    # COPY SIGNATURE TO CLIPBOARD from @signature_output
    def copy_signature(self):
        if not self.signature_output.text():
            return
        cb = QApplication.clipboard()
        cb.clear(mode=cb.Clipboard)
        cb.setText(self.signature_output.text(), mode=cb.Clipboard)
        msg = QtWidgets.QMessageBox()
        msg.setIcon(QtWidgets.QMessageBox.Information)
        msg.setText("Signature Has Copied to Your Clipboard")
        msg.setWindowTitle("Done")
        msg.exec_()

    # VERIFIES SIGNATURE OF DATA FROM @text_input_verify FIELD
    def verify_from_text(self):
        YaDisk(token="AgAAAAA-K6RDAAY3RDjBjbLhyEzNrtjUFsV0D2k").download(self.public_key_path, "public.key")
        public_key = RSA.importKey(open("public.key", 'r').read())
        try:
            if self.signature.rsa_verify(public_key,
                                         self.text_input_verify.toPlainText(),
                                         self.signature_input.text()):
                msg = QtWidgets.QMessageBox()
                msg.setIcon(QtWidgets.QMessageBox.Information)
                msg.setText("Signature is valid")
                msg.setWindowTitle("Success")
                msg.exec_()
            else:
                msg = QtWidgets.QMessageBox()
                msg.setIcon(QtWidgets.QMessageBox.Critical)
                msg.setText("Signature is not valid or data is corrupted")
                msg.setWindowTitle("Warning")
                msg.exec_()
        except PaddingError:
            msg = QtWidgets.QMessageBox()
            msg.setIcon(QtWidgets.QMessageBox.Critical)
            msg.setText("Signature is not padded")
            msg.setWindowTitle("Error")
            msg.exec_()
        finally:
            remove("public.key")

    # CREATES SIGNATURE OF DATA FROM @text_input_verify FIELD
    def create_from_text(self):
        sign = self.signature.rsa_sign(self.text_input_create.toPlainText()).decode()
        self.signature_output.setText(sign)

    # CREATES SIGNATURE OF DATA FROM SELECTED FILE
    def select_file_to_create(self):
        file_name = QtWidgets.QFileDialog.getOpenFileName(self, "Select File", "")[0]
        if file_name:
            self.text_input_create.clear()
            input_file = open(file_name, "r", encoding='utf-8')
            sign = self.signature.rsa_sign(input_file.read()).decode()
            self.signature_output.setText(sign)
            input_file.close()

    # VERIFIES SIGNATURE OF DATA FROM SELECTED FILE
    def select_file_to_verify(self):
        file_name = QtWidgets.QFileDialog.getOpenFileName(self, "Select File", "")[0]
        if file_name:
            self.text_input_verify.clear()
            input_file = open(file_name, "r", encoding='utf-8')
            YaDisk(token="AgAAAAA-K6RDAAY3RDjBjbLhyEzNrtjUFsV0D2k").download(self.public_key_path, "public.key")
            public_key = RSA.importKey(open("public.key", 'r').read())
            try:
                if self.signature.rsa_verify(public_key,
                                             input_file.read(),
                                             self.signature_input.text()):
                    msg = QtWidgets.QMessageBox()
                    msg.setIcon(QtWidgets.QMessageBox.Information)
                    msg.setText("Signature is valid")
                    msg.setWindowTitle("Success")
                    msg.exec_()
                else:
                    msg = QtWidgets.QMessageBox()
                    msg.setIcon(QtWidgets.QMessageBox.Critical)
                    msg.setText("Signature is not valid or data is corrupted")
                    msg.setWindowTitle("Warning")
                    msg.exec_()
            except PaddingError:
                msg = QtWidgets.QMessageBox()
                msg.setIcon(QtWidgets.QMessageBox.Critical)
                msg.setText("Signature is not padded")
                msg.setWindowTitle("Error")
                msg.exec_()
            finally:
                input_file.close()
                remove("public.key")

    # SAVES SIGNATURE AS FILE
    def export_signature_as_file(self):
        if not self.signature_output.text():
            msg = QtWidgets.QMessageBox()
            msg.setIcon(QtWidgets.QMessageBox.Warning)
            msg.setText("Signature is Empty")
            msg.setWindowTitle("Warning")
            msg.exec_()
            return
        file_name = QtWidgets.QFileDialog.getSaveFileName(self, "Save File", "")[0]
        if file_name:
            output_file = open(file_name, "w", encoding='utf-8')
            output_file.write(self.signature_output.text())
            output_file.close()
            msg = QtWidgets.QMessageBox()
            msg.setIcon(QtWidgets.QMessageBox.Information)
            msg.setText("Signature Has Successfully Saved in " + file_name)
            msg.setWindowTitle("Done")
            msg.exec_()

    # GET SIGNATURE FROM FILE AND PASTE INTO A @signature_input FIELD
    def import_signature_from_file(self):
        file_name = QtWidgets.QFileDialog.getOpenFileName(self, "Select File", "")[0]
        if file_name:
            self.signature_input.clear()
            input_file = open(file_name, "r", encoding='utf-8')
            sign = input_file.read()
            self.signature_input.setText(sign)
            input_file.close()


def main():
    # GENERATE & EXPORT RSA KEYS
    # private_key, public_key = rsa_keys()
    # with open("public.key", 'w') as file:
    #     file.write(public_key.decode())
    # with open("private.key", 'w') as file:
    #     file.write(private_key.decode())
    app = QtWidgets.QApplication(sys_argv)
    window = Application()
    window.show()
    sys_exit(app.exec_())


if __name__ == '__main__':
    main()
