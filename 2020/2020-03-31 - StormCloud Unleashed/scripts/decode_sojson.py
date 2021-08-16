# use this on a .js file with so_jsonv4 encoded content
import os 
import re
import subprocess 
import sys

def recursive_walk_directory(target_dir):
    '''
        input:
            target_dir (str) : A path to the directory you want to walk

        output:
            files (list) : A list of files in that directory
    '''
    files = []
    for d, s, file_list in os.walk(target_dir):
        for f in file_list:
            files.append(os.path.join(d,f))
    return files


# https://github.com/beautify-web/js-beautify
import jsbeautifier

if os.path.isfile(sys.argv[1]):
    files = [sys.argv[1]]
else:
    tmp_files = recursive_walk_directory(sys.argv[1])
    files = []
    for fil in tmp_files:
        if fil.endswith(".js"):
            files.append(fil)

print("Found {0} files with .js extensions to try and parse".format(len(files)))


for f in files:
    with open(f, 'r') as infile:
        data = infile.read()

    pattern = re.compile("\]\(null,.*\['",)
    matches = pattern.findall(data)
    if len(matches) < 1:
        print("File: {0} does not match delivery kit".format(f))
        continue

    for match in matches:
        match_data = match[8:-3] # these are the characters from the match that correspond to the string we need to decode
        continue

    char_code_array = []
    this_element = ""

    for char in match_data:
        try:
            a = int(char)
            this_element += char
        except:
            char_code_array.append(this_element)
            this_element = ""

    out = f + '.decoded'
    print("Writing output to: {0}".format(out))
    out_data = ""
    print(len(char_code_array))
    for cc in char_code_array:
        out_data += chr(int(cc))
    out_data = jsbeautifier.beautify(out_data)
    
    with open(out, 'w') as outfile:
        outfile.write(out_data)