import json
import re
import os
import subprocess
import sys
import getopt
import yaml
import argparse
import socket

def argumentsParsing():
    # Inicialize the parser
    parser = argparse.ArgumentParser(
    # Program Name
    prog= 'main.py',
    description= 'Snort Log Parser',
    # End of help message
    epilog= './main.py -c <config_file> -a <src ip address'
    )

    # Configuration file
    parser.add_argument('-c', '--config', required=True, help= "configuration file")

    return parser.parse_args()

def yamlParsing(fileName):
    try:
        file = open(fileName, 'r')
    except FileNotFoundError:
        print("Arquivo não existe")
        sys.exit(2)
    
    yamlFile = yaml.safe_load(file)
    return yamlFile['paths'], yamlFile["file_names"], yamlFile['ssh']

def main():
    args = argumentsParsing()
    paths, names, ssh = yamlParsing(args.config)

    # open log file
    jsonFile = open(paths['log'] + names['log'])
    IDS = {}

    # iterate over row in that file
    for row in jsonFile:
        data = json.loads(row)
        id = re.split(":", data['rule'])[1]
        IDS[id] = True

    # assign rule directory
    directory = paths['rule']
    # rule file that will be sent to others snort
    pathNewRules = paths['new_rules'] + names['new_rules']

    try:
        newRules = open(pathNewRules, "w")
    except FileNotFoundError:
        print("Não foi possivel abrir o arquivo de novas regras")
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
    myIP = socket.gethostbyname(socket.gethostname())

    for dispositivo in ssh:
        if ssh[dispositivo]['addr'][5:] == myIP:
            continue

        sshAddr = ssh[dispositivo]['addr'] + ":" + ssh[dispositivo]['path']
        subprocess.run(["scp", pathNewRules, sshAddr])


if __name__ == "__main__":
    main()