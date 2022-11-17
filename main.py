import json
import re
import os
import subprocess
import sys
import getopt
import yaml


def argumentsParsing(argv):
    try:
        opts, args = getopt.getopt(argv, 'hc:', 'config')
    except getopt.GetoptError:
        print('main.py -c <configfile>')
        sys.exit(2)
    
    parameters = []

    if opts:
        parameters = opts
    elif args:
        parameters = args
    else:
        print('main.py -c <configfile>')
        sys.exit(2)
    
    return parameters 


def yamlParsing(fileName):
    try:
        file = open(fileName, 'r')
    except FileNotFoundError:
        print("Arquivo não existe")
        sys.exit(2)
    
    yamlFile = yaml.safe_load(file)
    return yamlFile['paths'], yamlFile["file_names"]


def main():
    args = argumentsParsing(sys.argv[1:])
    paths, names = yamlParsing(args[-1])

    # open log file
    jsonFile = open(paths['log'] + names['log'])
    IDS = {}

    # iterate over row in that directory
    for row in jsonFile:
        data = json.loads(row)
        id = re.split(":", data['rule'])[1]
        IDS[id] = True

    # assign directory
    directory = paths['rule']
    pathNewRules = paths['new_rules'] + names['new_rules']

    try:
        newRules = open(pathNewRules, "w")
    except FileNotFoundError:
        print("Arquivo de log não encontrado")
        sys.exit(2)
    
    # iterate over files in
    # that directory
    for filename in os.listdir(directory):
        f = os.path.join(directory, filename)
        # checking if it is a file
        if not os.path.isfile(f):
            continue
    
        try:
            File = open(f)
        except FileNotFoundError:
            print(f"Arquivo de regra não encontrado: {f}")
            sys.exit(2)


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
            
    newRules.close()
    sshFile = open("files/ssh_address_and_path.txt")

    for sshAddr in sshFile:
        subprocess.run(["scp", pathNewRules, sshAddr + "rules.rules"])


if __name__ == "__main__":
    main()