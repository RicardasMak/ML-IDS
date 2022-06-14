"""
In this class dataset will be pre-processed for machine learning algorithm with fallowing steps:
1. imported dataset "log.csv"
2. seperate dependant variables (targets or labels) from dataset
3. ecode dependant variables
4. balance dataset by oversampling.
5. split dataset to training (80%) and testing (20%)
"""

import pandas as pd
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split


# Import dataset from csv to
def import_dataset():
    dataset = pd.read_csv('log.csv')

    # remove duplicate data points
    dataset = dataset.drop_duplicates()
    # shuffle rows
    dataset = dataset.sample(frac=1).reset_index(drop=True)

    print('Dataset rows: ', dataset.shape[0])
    print('Dataset columns: ', dataset.shape[1])

    return dataset


# split dataset from dependant variable
def split_dependant_var():
    dataset = import_dataset()

    X = dataset.iloc[:, :-1].values
    y = dataset.iloc[:, -1].values

    return X, y


# encode dependant variables
def encode_dependand_var():
    X, y = split_dependant_var()

    le = LabelEncoder()
    y = le.fit_transform(y)

    return X, y


# splitting data into training set and test set
def dataset_split():
    X, y = encode_dependand_var()

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=0)

    return X_train, X_test, y_train, y_test
