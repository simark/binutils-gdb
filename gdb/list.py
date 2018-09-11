# Execute with:
#   ./gdb --data-directory=data-directory -x list.py -ex "python l()" <executable>
#
# Use -readnow to read all compunits at start time.

def l():
    for o in gdb.objfiles():
        print(o)
        for c in o.compunits():
            print('    ' + str(c))
            for s in c.symtabs():
                print('       ' + str(s))
