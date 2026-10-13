""" Program to harvest krillion.io's answers and determine the best score """
import requests
from datetime import datetime
import concurrent.futures

def Query(ans, pid):
    #iterate through each answer
    resp = requests.post("https://krillion.io/api/submit", json={
        "date": datetime.today().strftime('%Y-%m-%d'),
        "promptId": pid,
        "answer": str(ans),
        "previewCorrection": True,
        "playerId": "cbbc467b-2861-43ca-bbe8-ad9b011419ff"
    })
    respJ = resp.json()
    if respJ["accepted"] and respJ["score"] == 100:
        print(f"Answer to {pid} is {str(ans)}")
        return True
    return False

if __name__ == "__main__":
    #get all answers
    answersReq = requests.get("https://krillion.io/api/answer-popularity?date=2026-10-13")
    answers = answersReq.json()

    #input every answer
    for i in range(7):
        pid = f"p{i+1}"
        processes = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as e:
            for x in answers["prompts"][pid].keys():
                processes.append(e.submit(Query, x, pid))
