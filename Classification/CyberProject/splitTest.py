import pandas as pd
from sklearn.model_selection import StratifiedKFold

data = pd.read_csv('trafficTest.csv')
dir = "trafficTestSet"
skf = StratifiedKFold(n_splits=40, shuffle=True, random_state=42)

for i, (_, test_index) in enumerate(skf.split(data, data['label'])):
    split_data = data.iloc[test_index].drop(columns=['label'])
    split_data.to_csv(f'{dir}/testSet_{i + 1}.csv', index=False)
    
print("Data split into 40 CSV DONE!")