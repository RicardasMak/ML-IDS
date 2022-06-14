#!/usr/bin/env python3.9
"""
This is the main class which is used to communicate with the user via CLI menu.
"""
import os
import sys
import tools
from tools.input_handler import check_ip
from tools.ML_training import logical_regression, KNN, decision_tree, random_forest

start_dataset = False
startIDS = False
ip, nic = tools.get_nic_name()
local_port = tools.get_local_interface.get_ports()


# start function to build dataset
def build_dataset():
    start_dataset = True

    malicious_ip = check_ip()

    print('Building dataset (Ctrl+c to stop)')
    tools.sniffer(start_dataset, ip, nic, malicious_ip, local_port)


# sub-menu for building ml model
def ml_model_train():
    os.system('clear')

    while True:
        print('''
        Please select witch algorithm apply for ML model:
            1. Decision Tree
            2. Random Forest
            3. Logistic Regression
            4. KNN
            5. Go Back
        ''')

        try:
            choise = int(input('Please select function: '))
            os.system('clear')
        except ValueError:
            print('Wrong input')
            #ml_model_train()

        function = {
            1: decision_tree,
            2: random_forest,
            3: logical_regression,
            4: KNN,
            5: menu
        }

        function.get(choise, handler)()


# sub-menu for IDS
def start_IDS():
    global choise
    os.system('clear')

    while True:
        print('''
        Please select witch ML model to use for IDS:
            1. Decision Tree
            2. Random Forest
            3. Logistic Regression
            4. KNN
            5. Go Back
        ''')

        try:
            choise = int(input('Please select function: '))
            os.system('clear')
        except ValueError:
            print('Wrong input')
            start_IDS()

        function = {
            1: 'decision_tree.sav',
            2: 'random_forest.sav',
            3: 'logistic_regression.sav',
            4: 'KNN.sav',
            5: 'menu'
        }

        model = function.get(choise, handler())

        is_model = False

        # Will check if ML model is trained
        if model == 'menu':
            menu()
        elif model:
            is_model = os.path.exists(model)

        if is_model:
            startIDS = True
            tools.ids(startIDS, nic, ip, model)
        else:
            print('Cannot find', model,', try to train again')


def exit_program():
    return sys.exit(0)

def handler():
    print('Wrong input')

# Main menu of the tool
def menu():
    global choise

    while True:
        os.system('clear')
        print('''
            1. Build dataset
            2. Build machine learning model
            3. Start IDS
            4. Exit
        ''')

        try:
            choise = int(input('Please select function: '))
        except ValueError:
            print('Invalid input')
            menu()

        functions = {
            1: build_dataset,
            2: ml_model_train,
            3: start_IDS,
            4: exit_program
        }

        functions.get(choise, handler)()


if __name__ == '__main__':
    menu()
