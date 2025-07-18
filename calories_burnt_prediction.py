import numpy as np
import pandas as pd
import pickle
import seaborn as sns
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LinearRegression
from sklearn.tree import DecisionTreeRegressor
from sklearn.ensemble import RandomForestRegressor
from sklearn import metrics

# Load datasets
df1 = pd.read_csv("calories.csv")
df2 = pd.read_csv("exercise.csv")

# Merge datasets
df = pd.concat([df2, df1["Calories"]], axis=1)
df.drop(columns=["User_ID"], inplace=True)

# Encode categorical variable
df["Gender"] = pd.get_dummies(df["Gender"], drop_first=True)

# Split features and target
X = df.drop(columns=["Calories"], axis=1)
y = df["Calories"]
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=1)

# Train models and find the best one
models = {
   
    "LinearRegression": LinearRegression(),
    "DecisionTreeRegressor": DecisionTreeRegressor(),
    "RandomForestRegressor": RandomForestRegressor()
}

best_model = None
best_score = float("-inf")

for name, model in models.items():
    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)
    r2_score = metrics.r2_score(y_test, y_pred)
    print(f"{name} R2 Score: {r2_score}")
    
    if r2_score > best_score:
        best_score = r2_score
        best_model = model

# Save the best model
with open("best_model.pkl", "wb") as f:
    pickle.dump(best_model, f)

print(f"Best model saved: {best_model}")