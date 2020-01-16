#!/usr/bin/env python
'''The program updates some content in one file.
'''
LEAD="### BEGIN NCL ADD CONTENT"
TAIL="### END NCL ADD CONTENT"

def usage():
    print "%s content OutputFile" % sys.argv[0]
    print "%s file contentFile outputFile" % sys.argv[0]
def update_part(part, fcontent):
    '''The func update part in fcontent.'''
    pbeg = fcontent.find(LEAD)
    pend = fcontent.find(TAIL)
    ncontent = ''
    if pbeg != -1:
        #find it, update it.
        if pend == -1:
            print "Error: only find LEAD, can not find TAIL"
            exit(-1)
        ncontent = fcontent[0:pbeg]
        ncontent += LEAD
        ncontent += '\n'
        ncontent += part
        ncontent += '\n'
        ncontent += fcontent[pend:]
    else:
        # do not add before, tail the part.
        ncontent = fcontent
        ncontent += '\n'
        ncontent += LEAD
        ncontent += '\n'
        ncontent += part
        ncontent += '\n'
        ncontent += TAIL
        ncontent += '\n'
        
    return ncontent
        
    
def test():
    ncontent = update_part('b', 'a')
    assert ncontent == 'a\n### BEGIN NCL ADD CONTENT\nb\n### END NCL ADD CONTENT\n'
    ncontent = update_part('c', ncontent)
    assert ncontent == 'a\n### BEGIN NCL ADD CONTENT\nc\n### END NCL ADD CONTENT\n'
    ncontent = update_part('b\nc', 'a\nb')
    assert ncontent == 'a\nb\n### BEGIN NCL ADD CONTENT\nb\nc\n### END NCL ADD CONTENT\n'
    ncontent = update_part('c\nd', ncontent)
    assert ncontent == 'a\nb\n### BEGIN NCL ADD CONTENT\nc\nd\n### END NCL ADD CONTENT\n'
    
    pass
def main():
    '''The func is the main func.'''
    import sys
    if (len(sys.argv) == 2) and (sys.argv[1] == "test"):
        test()
        print "Pass all test"
        exit()
    elif (len(sys.argv) == 3):
        file = sys.argv[2]
        part = sys.argv[1]
        with open(file, "r") as afile:
            fcontent = afile.read()
        ncontent = update_part(part, fcontent)
        with open(file, 'w') as afile:
            afile.write(ncontent)
    elif (len(sys.argv) == 4) and (sys.argv[1] == 'file'):
        pfile = sys.argv[2]
        file = sys.argv[3]
        with open(pfile, "r") as afile:
            part = afile.read()
        with open(file, "r") as afile:
            fcontent = afile.read()
        ncontent = update_part(part, fcontent)
        with open(file, 'w') as afile:
            afile.write(ncontent)
        
    else:
        usage(sys.argv[0])


if __name__ == "__main__":
    main()

