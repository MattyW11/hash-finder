'''
ToDo
- Let user select a specific hash to search for
'''

import os
import platform
import re
import argparse

class customArgParser(argparse.ArgumentParser): 
    
    def error(self, message): #overrides the argparse error() class with a custom message
        '''Custom error for argparser'''
        print(f'\n Argument Error: {message}\n')
        exit(2)

    #Check if directory/file exists
    @staticmethod
    def parserPath(filepath):
        if os.path.exists(filepath):
            return True
        else:
            return False

class hashFinder():
    #Global variables
    #Dictionary of hashes
    hash_patterns = {
    "MD5, RIPEMD": r'\b[a-fA-F0-9]{32}\b',
    "SHA-1, SHA-3-256, RIPEMD-160": r'\b[a-fA-F0-9]{40}\b',
    "SHA-256, SHA-512/256, Blake2s": r'\b[a-fA-F0-9]{64}\b',
    "SHA-512, Keccak-512, Blake2b": r'\b[a-fA-F0-9]{128}\b',
    "SHA-384, SHA-3-384": r'\b[a-fA-F0-9]{96}\b',
    "SHA-384 truncated, SHA-512/224": r'\b[a-fA-F0-9]{48}\b',
    "SHA-224, SHA-3-224, SHA-224 trunc": r'\b[a-fA-F0-9]{56}\b',
    "Base64": r'\b[a-zA-Z0-9/+]{43}={0,2}\b',
    "CRC-24": r'\b[a-fA-F0-9]{24}\b',
    "SHA-1 base32": r'\b[a-fA-F0-9]{36}\b',
    "bcrypt": r'\$2[ayb]\$.{56}\b',
    "scrypt": r'\$7\$.{120}\b',
    "TrueCrypt": r'\$tcw\$.{60}\b',
    "PBKDF2 with SHA-256": r'\$pbkdf2-sha256\$.{64}\b',
    "PBKDF2 with SHA-512": r'\$pbkdf2-sha512\$.{128}\b',
    "CRC32": r'\b[a-fA-F0-9]{8}\b'
}
    
    def __init__(self, *args, **kwargs):
        self.path = kwargs.get('path')
        self.isFile = kwargs.get('isFile', False) 
        self.isDir = kwargs.get('isDir', False)
        self.recursive = kwargs.get('recursive', False)
        self.no_hidden = kwargs.get('no_hidden', False)
        self.unauthorised_access = []

    def scanFile(self, target):
        '''Scan a file based on user input'''
        try:
            unauthorised_access = []
            if os.access(target, os.R_OK):
                target_result = []
                with open(target, 'r', encoding='utf-8') as file:
                    for line_num, line in enumerate(file, start=1):
                        for key, pattern in hashFinder.hash_patterns.items():
                            match = re.search(pattern, line)
                            if match:
                                target_result.append((key, match.group(0), line_num, target))
                if target_result:
                    for result in target_result:
                        print(f'{result[0]:<40} {result[1]:<80} {result[2]:<15} {result[3]:<50}')
            elif not os.access(target, os.R_OK):
                self.unauthorised_access.append(target) #Write failed file access to list
            else:
                print('Failed to initialise file scan', target)
                
        except Exception as e:
            print('Failed to scan file:', target, '\n', e)

    def scanDir(self, target):
            '''Scan a directory based on user input'''
            try:
                for root, dirs, files in os.walk(target):
                    if self.no_hidden:
                        if platform.system() == 'Linux':
                            dirs[:] = [d for d in dirs if not d.startswith('.')] #Excludes hidden (start with period) files from scan. The dirs[:] means we replace the content of the dirs list each time
                        elif platform.system() == 'Windows':
                            dirs[:] = [d for d in dirs if not (os.stat(os.path.join(root, d)).st_file_attributes & stat.FILE_ATTRIBUTE_HIDDEN)]
                    for file in files:
                        file_path = os.path.join(root, file)
                        self.scanFile(file_path)

                        for dir in dirs: #Write our dirs we couldn't access to unauthorised_access
                            dir_path = os.path.join(root, dir)
                            if not os.access(dir_path, os.R_OK):
                                if dir_path not in self.unauthorised_access: #Make sure the path isn't already in the list
                                    self.unauthorised_access.append(dir_path)
                            
                    if not self.recursive:
                        break
                    
            except Exception as e:
                print('Failed to scan directory', target, '\n', e)
                    
    def initialiseScan(self):
        '''Initialise scan'''
        try:
            if self.isFile:
                print(f'{"Hash Type":<40} {"Hash":<80} {"Line Number":<15} {"File Path":<50}')
                print('='*200)
                self.scanFile(self.path)
            elif self.isDir:
                print(f'{"Hash Type":<40} {"Hash":<80} {"Line Number":<15} {"File Path":<50}')
                print('='*200)
                self.scanDir(self.path)
            else: #future expansion
                print('Error initialising file scan')

            if self.unauthorised_access: #Once all the scans are complete, print any files/folders we couldn't access
                print('\n')
                print('='*200)
                print('Failed to access the following files/folder:')
                print('\n')
                for file in self.unauthorised_access:
                    print(file)
        except Exception as e:
            print('Error:', e)         

def main():
    #Define arguments
    parser = customArgParser(description='Find potential hash strings in files\n'
                                          'Hash strings could represent multiple potential hash algorithms beyond those listed in this program\n'
                                          'Any discovered hashes should be checked to confirm which hash algorithm it is from',
                                           formatter_class=argparse.RawDescriptionHelpFormatter
                                        )
    
    parser.add_argument('--version', action='version', version='hash-finder 1.0.337')
    parser.add_argument('-p', '--path', help='Path to directory or file. Example: /var/www/data or var/www/data/file.js')
    parser.add_argument('--recursive', action='store_true', help='Recursively search subdirectories')
    parser.add_argument('--no-hidden', action='store_true', help='Exclude hidden files and folders from scan')
    
    args = parser.parse_args()

    #Check if path and filename exist
    if args.path and not parser.parserPath(args.path):
        parser.error('The filename or path provided does not exist')
    elif args.path:
        if os.path.isfile(args.path):
            initiate = hashFinder(
                path = args.path,
                isFile = True
            )
        elif os.path.isdir(args.path):
            initiate = hashFinder(
                path = args.path,
                isDir = True,
                recursive = args.recursive,
                no_hidden = args.no_hidden
            )
    else: #future expansion
        print('Failed to invoke scan')

    initiate.initialiseScan()

##Run main()
if __name__ == '__main__':
    main()