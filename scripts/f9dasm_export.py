#export annotated disassembly to f9dasm info files
#@author Jack Case
#@category Disassembly
#@keybinding 
#@menupath 
#@toolbar 
#@runtime PyGhidra

from os import path
from ghidra.program.model.address import AddressSet


OPTIONS = ["noaddr",
           "nohex",
           "6808",
           "noconv",
           "noasc"]


state = getState()
program =  state.getCurrentProgram()
name = program.getName()

memory = program.getMemory()
blocks = memory.getBlocks()
rom_files = memory.getAllFileBytes()
symbols = program.getSymbolTable()

def output_code_comments(base_address, last_address, info_file):

    listing = program.getListing()

    comment_iter = listing.getCommentAddressIterator(AddressSet(base_address, last_address), True)
    
    for comment_address in comment_iter:
        line_comment = listing.getComment(0, comment_address)
        pre_comment = listing.getComment(1, comment_address)

        if line_comment:
            info_file.write(f"lcomment {comment_address} {line_comment}\n")

        if pre_comment:
            info_file.write(f"comment {comment_address} {pre_comment}\n")

def output_code_equates(base_address, last_address, info_file):

    equate_table = program.getEquateTable()

    equate_iter = equate_table.getEquates()
    print([(equ.getName(), equ.getValue()) for equ in equate_iter])
    pass 

def output_code_labels(info_file):
    for symbol in symbols.getSymbolIterator():
        print(symbol)
        info_file.write(f"label {symbol.getAddress()} {symbol.getName()}\n")
    
    pass
    

print([file.getFilename() for file in rom_files])

files = list()

# for each rom block, get the address offset and write it to the .info file
info_file = open(path.join("/tmp", f"disassembly.info"), "w")

option_strings = (f"option {option}\n" for option in OPTIONS)

info_file.write("".join(option_strings))

for file in rom_files:

    filename = file.getFilename()
    file_base_address = memory.locateAddressesForFileBytesOffset(file, 0)[0]
    file_end_address = file_base_address.add(file.getSize() - 1)

    files.append(file_base_address)
    files.append(file_end_address)

    info_file.write(f"file {filename} {file_base_address}\n")

least_address = min(files)
most_address = max(files)

print(least_address)
print(most_address)

# for each instruction in the listing write any comments to the .info file
output_code_comments(least_address, most_address, info_file)


# put each label into the info file
# output_code_equates(file_base_address, file_end_address, info_file)

# output labels into the info file
output_code_labels(info_file)

# call f9dasm for each file with the generated info file

info_file.close()