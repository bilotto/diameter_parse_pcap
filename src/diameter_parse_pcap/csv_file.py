import csv
import os

class CsvFile:
    def __init__(self, filename: str, csv_columns: list, replace_existing: bool = False):
        self.filename = filename
        if not os.path.exists(filename) or replace_existing:
            self.file_handler = open(filename, 'w')
            self.csv_writer = csv.DictWriter(self.file_handler, fieldnames=csv_columns)
            self.csv_writer.writeheader()
        else:
            self.file_handler = open(filename, 'a')
            self.csv_writer = csv.DictWriter(self.file_handler, fieldnames=csv_columns)

    def write_row(self, row: dict):
        self.csv_writer.writerow(row)

    def close(self):
        self.file_handler.close()

    def flush(self):
        self.file_handler.flush()

    def get_csv_columns(self):
        return self.csv_writer.fieldnames


