import os
import json
import csv
from collections import Counter

def countCVE(filename):
    with open(filename, "r") as f:
        data = json.loads(f.read())
        keys = data.keys()
        with open("vulncount.csv", "w") as csvfile:
            fieldnames=["Image", "num_vulns"]
            writer = csv.writer(csvfile)
            writer.writerow(fieldnames)
            for i in keys:
                count = len(data[i]["matches"])
                writer.writerow([i]+[count])

def countPackages(filename):
    with open(filename, "r") as f:
        data = json.loads(f.read())
        keys = data.keys()
        c = Counter()

        for i in keys:
            matches = data[i]["matches"]
            for m in matches:
                c.update({m["artifact"]["name"] : 1})
        
        with open("pkgcount.csv", "w") as csvfile:
            fieldnames=["Package", "Count"]
            writer = csv.writer(csvfile)
            writer.writerow(fieldnames)
            for key, value in c.items():
                writer.writerow([key]+[value])

def countCritCVE(filename):
    with open(filename, "r") as f:
        data = json.loads(f.read())
        keys = data.keys()
        c = Counter()

        for i in keys:
            matches = data[i]["matches"]
            for m in matches:
                if m["vulnerability"]["severity"] == "High":
                    c.update({m["vulnerability"]["id"] : 1})

        with open("critcount.csv", "w") as csvfile:
            fieldnames=["CVE", "Count"]
            writer = csv.writer(csvfile)
            writer.writerow(fieldnames)
            for key, value in c.items():
                writer.writerow([key]+[value])

def countSeverity(filename):
    with open(filename, "r") as f:
        data = json.loads(f.read())
        keys = data.keys()
        c = Counter()

    for i in keys:
            matches = data[i]["matches"]
            for m in matches:
                severity = m["vulnerability"]["severity"]
                if severity == "Critical":
                    c.update({"Critical" : 1})
                elif severity == "High":
                    c.update({"High": 1})
                elif severity == "Medium":
                    c.update({"Medium": 1})
                elif severity == "Low":
                    c.update({"Low": 1})
                elif severity == "Negligible":
                    c.update({"Negligible": 1}) 
                else:
                    c.update({"Unknown": 1}) 
    
    print(c)
    

def groupImages(filename):
    with open(filename, "r") as f:
        data = json.loads(f.read())
        keys = data.keys()
        c = {}
    
    for i in keys:
            matches = data[i]["matches"]
            for m in matches:
                severity = m["vulnerability"]["severity"]
                if severity == "Critical":
                    c.update({i : "Critical"})
                    break
                elif severity == "High":
                    if c.get(i) != "Critical":
                        c.update({i : "High"})
                elif severity == "Medium":
                    if c.get(i) not in ["Critical", "High"]:
                        c.update({i : "Medium"})
                elif severity == "Low":
                    if c.get(i) not in ["Critical", "High", "Medium"]:
                        c.update({i : "Low"})
                elif severity == "Negligible":
                    if c.get(i) not in ["Critical", "High", "Medium", "Low"]:
                        c.update({i : "Negligible"})
                else:
                    c.update({i: "Unknown"}) 
    
    with open("severitycount.csv", "w") as csvfile:
            fieldnames=["Image", "Severity"]
            writer = csv.writer(csvfile)
            writer.writerow(fieldnames)
            for key, value in c.items():
                writer.writerow([key]+[value])

if __name__ == '__main__':
    filename = "scan_results.json"
    groupImages(filename)