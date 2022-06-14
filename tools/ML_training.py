"""
This class is used to train machine learning model and save it as file by using pickle function.
It provides algorithm such as logistic regression, KNN, random forest and decision tree.
For logistic regression and KNN dataset features were broth to the same scale by applying standardization.
"""
import pickle
from tools import dataset_split as dataset
from sklearn.metrics import confusion_matrix, accuracy_score
from sklearn.neighbors import KNeighborsClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline


# Train ML by using logical regression algorithm with standardized dataset
def logical_regression():
    X_train, X_test, y_train, y_test = dataset()

    # solver and max iter was specified to avoid error
    # multinomial was chosen because dataset contains 4 dependant variables
    pipeline = Pipeline([('scaler', StandardScaler()), ('lg', LogisticRegression(solver='lbfgs', max_iter=1000,
                                                                                 multi_class='multinomial'))])
    pipeline.fit(X_train, y_train)

    predict = pipeline.predict(X_test)
    matrix = confusion_matrix(y_test, predict)

    print('========== Linear Regression ==========')
    print('confusions matrix: ')
    print(matrix)

    score = pipeline.score(X_test, y_test)
    print('accuracy: ', score * 100, '%\n')

    save_state(pipeline, 'logistic_regression.sav')


# train ML by using K Nearest neighbors (K-NN) algorithm with standardized dataset
def KNN():
    X_train, X_test, y_train, y_test = dataset()

    pipeline = Pipeline([('scaler', StandardScaler()), ('knn', KNeighborsClassifier())])
    pipeline.fit(X_train, y_train)

    predict = pipeline.predict(X_test)
    matrix = confusion_matrix(y_test, predict)

    print('========== KNN ==========')
    print('confusions matrix: ')
    print(matrix)

    score = pipeline.score(X_test, y_test)
    print('accuracy: ', score * 100, '%\n')

    save_state(pipeline, 'KNN.sav')


# train ML by using Decision Tree algorithm
def decision_tree():
    X_train, X_test, y_train, y_test = dataset()

    dt = DecisionTreeClassifier()
    dt.fit(X_train, y_train)

    predict = dt.predict(X_test)
    matrix = confusion_matrix(y_test, predict)

    print('========== Decision Tree ==========')
    print('confusions matrix: ')
    print(matrix)

    accuracy = accuracy_score(y_test, predict)
    print('accuracy: ', accuracy * 100, '%\n')

    save_state(dt, 'decision_tree.sav')


# train ML by using Random Forest algorithm with 100 Decision Trees
def random_forest():
    X_train, X_test, y_train, y_test = dataset()

    rd = RandomForestClassifier(n_estimators=100)
    rd.fit(X_train, y_train)

    predict = rd.predict(X_test)
    matrix = confusion_matrix(y_test, predict)

    print('========== Random Forest ==========')
    print('confusions matrix: ')
    print(matrix)

    accuracy = accuracy_score(y_test, predict)
    print('accuracy: ', accuracy * 100, '%\n')

    save_state(rd, 'random_forest.sav')


# save state of ML model
def save_state(model, name):
    pickle.dump(model, open(name, 'wb'))
