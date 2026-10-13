""" Program to simply format the exposed API results from krillion.io """
import requests
from datetime import datetime

if __name__ == "__main__":
    resp = requests.get(f"https://krillion.io/api/reveal?date={datetime.today().strftime('%Y-%m-%d')}").json()

    for x in resp["prompts"]:
        print(x["id"], end=": ")
        for ans in x["answers"]:
            if ans["score"] == 100:
                print(ans["answer"])
        print("")
