import os

def printToFile(my_set):
    file = open("image_list.txt", "w")
    for val in my_set:
        file.write(val + "\n")
    file.close()

def generateList():
    my_set = {}
    my_set = set()
    for i in range(ord('a'), ord('z')+1):
        for j in range(ord('a'), ord('z')+1):
            search_chars = chr(i) + chr(j)
            data = os.popen(
                "docker search --filter is-official=true --format \"{{.Name}}\" " + search_chars).read()
            data = data.split()
            my_set.update(data)
            if len(my_set) >= 163:
                printToFile(my_set)
                return

if __name__ == '__main__':
    generateList()