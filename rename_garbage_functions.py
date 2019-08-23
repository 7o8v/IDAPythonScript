from idautils import *
from idaapi import *
from idc import *

# Return function disasm string
def getFuncDisasm(func):
    insList = []
    for (startea, endea) in Chunks(func):
        for head in Heads(startea, endea):
            insList.append(GetDisasm(head))
    return "\n".join(insList)

# Compare two functions by instructions
def compare_function(func_1, func_2):
    if(getFuncDisasm(func_1) == getFuncDisasm(func_2)):
        return True
    else:
        return False

def find_garbage_func(garbage_name):
    the_first_garbage_func = None
    # Find the first
    for segea in Segments():
        for funcea in Functions(segea, SegEnd(segea)):
            functionName = GetFunctionName(funcea)
            if functionName == garbage_name:
                the_first_garbage_func = funcea
    print("--*-- Disasm Garbage Func --*--\n"+getFuncDisasm(the_first_garbage_func))
    # Find all                
    i = 0
    for segea in Segments():
        for funcea in Functions(segea, SegEnd(segea)):
            if compare_function(funcea, the_first_garbage_func):
                # Rename garbage function
                set_name(funcea, "Garbage_{}".format(i))
                i += 1
                print("Find garbage func : {}".format(GetFunctionName(funcea)))
                
                
            
#find_garbage_func('sub_40189C')