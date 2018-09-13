
for i in range(0,50):
    j = 16 * i
    print "extern __declspec(dllexport) void et" + str(j) + "(X<" + str(j) + ">)"
    print "{"
    print "}\n"
