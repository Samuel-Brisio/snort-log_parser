import json
import re
import os

# open log file
jsonFile = open("example_file/alert_json.txt")
IDS = {}

# iterate over row in that directory
for row in jsonFile:
    data = json.loads(row)
    id = re.split(":", data['rule'])[1]
    IDS[id] = True

# assign directory
directory = 'example_file/rules'
newRules = open("new_rules.rules", "w")
 
# iterate over files in
# that directory
for filename in os.listdir(directory):
    f = os.path.join(directory, filename)
    # checking if it is a file
    if not os.path.isfile(f):
        continue
    
    File = open(f)
    for row in File:
        isNotRule = re.search("#", row)
        
        if isNotRule or len(row) == 0 or row == '\n':
            continue

        Lista = re.findall("[;][\s]*[s][i][d][\s]*[:][\d]+[;]", row)
        
        # Se a lista terá que ter tamanho um, pois todas as linhas que não estão comentadas são regras
        # E toda regra tem um id
        if (len(Lista) != 1):
            print(row)
            assert True, "Tratar esse caso"

        id = re.findall("[\d]+", Lista[0])[0]

        if(IDS.get(id)):
            newRules.write(row)
        